# jpeg_stego.py
# EncryptMaster — JPEG Stego (DCT, mid-frequencies, AES-GCM)
# Nodes:
#   - Jpeg_Stego_EmbedText   : IMAGE, text, passphrase, quality -> IMAGE
#   - Jpeg_Stego_ExtractText : IMAGE, passphrase                -> STRING
#
# NOTE (prototype robuste FB):
# - Encode dans les AC "mid-frequency" du canal Y après quantification.
# - Plus résistant à une recompression (Q~90->80) qu'un LSB spatial.
# - Capacité modérée (quelques Ko).
#
# Limites:
# - Recompresssions très agressives (Q<=60), gros redimensionnements/filters -> perte possible.

import io
import os
import math
import struct
from typing import Tuple

import numpy as np
from PIL import Image
import torch

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CATEGORY = "EncryptMaster"

# ---------- Crypto helpers (mêmes fondations que le pack) ----------
def _derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    if not passphrase:
        raise ValueError("passphrase cannot be empty")
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, passphrase: str, associated_data: str = "") -> Tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    aad = associated_data.encode("utf-8") if associated_data else None
    cipher = aes.encrypt(nonce, plaintext, aad)
    return salt, nonce, cipher

def decrypt_bytes(salt: bytes, nonce: bytes, cipher: bytes, passphrase: str, associated_data: str = "") -> bytes:
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    aad = associated_data.encode("utf-8") if associated_data else None
    return aes.decrypt(nonce, cipher, aad)

# ---------- Tensor <-> PIL ----------
def tensor2pil(img_tensor: torch.Tensor) -> Image.Image:
    t = img_tensor[0].detach().cpu()
    arr = t.numpy()
    arr = np.clip(arr, 0.0, 1.0)
    arr = (arr * 255.0).round().astype(np.uint8)
    if arr.ndim == 2:
        arr = np.stack([arr, arr, arr], axis=-1)
    if arr.ndim == 3 and arr.shape[2] > 3:
        arr = arr[:, :, :3]
    return Image.fromarray(arr, mode="RGB")

def pil2tensor(img: Image.Image):
    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.array(img, dtype=np.float32) / 255.0
    t = torch.from_numpy(arr).unsqueeze(0)  # [1,H,W,C]
    return (t,)

# ---------- JPEG DCT helpers (8x8, canal Y) ----------
# Matrice DCT 8x8 (orthonormée)
def _dct_matrix(n=8):
    A = np.zeros((n, n), dtype=np.float64)
    for u in range(n):
        for x in range(n):
            alpha = math.sqrt(1.0/n) if u == 0 else math.sqrt(2.0/n)
            A[u, x] = alpha * math.cos(((2*x + 1) * u * math.pi) / (2 * n))
    return A

A8 = _dct_matrix(8)
A8T = A8.T

# Table luminance standard (base JPEG, sera "scalée" selon quality)
_QY_STD = np.array([
    [16,11,10,16,24,40,51,61],
    [12,12,14,19,26,58,60,55],
    [14,13,16,24,40,57,69,56],
    [14,17,22,29,51,87,80,62],
    [18,22,37,56,68,109,103,77],
    [24,35,55,64,81,104,113,92],
    [49,64,78,87,103,121,120,101],
    [72,92,95,98,112,100,103,99],
], dtype=np.float64)

# Qualité JPEG -> scale quantization (approximation standard)
def _scale_qtable(q: int) -> np.ndarray:
    q = max(10, min(95, int(q)))
    if q < 50:
        s = 5000 / q
    else:
        s = 200 - 2 * q
    Q = np.floor((_QY_STD * s + 50) / 100)
    Q[Q < 1] = 1
    Q[Q > 255] = 255
    return Q

# Zigzag order pour ordonner (u,v)
_ZZ = np.array([
    (0,0),(0,1),(1,0),(2,0),(1,1),(0,2),(0,3),(1,2),
    (2,1),(3,0),(4,0),(3,1),(2,2),(1,3),(0,4),(0,5),
    (1,4),(2,3),(3,2),(4,1),(5,0),(6,0),(5,1),(4,2),
    (3,3),(2,4),(1,5),(0,6),(0,7),(1,6),(2,5),(3,4),
    (4,3),(5,2),(6,1),(7,0),(7,1),(6,2),(5,3),(4,4),
    (3,5),(2,6),(1,7),(2,7),(3,6),(4,5),(5,4),(6,3),
    (7,2),(7,3),(6,4),(5,5),(4,6),(3,7),(4,7),(5,6),
    (6,5),(7,4),(7,5),(6,6),(5,7),(6,7),(7,6),(7,7)
], dtype=np.int32)

# Indices AC "mid-frequency" (on évite DC et hautes fréquences trop fragiles)
_MID_AC_IDX = [i for i in range(10, 40)]  # empirique, fonctionne bien

def _blockify(arr: np.ndarray, bs=8):
    h, w = arr.shape
    H = (h + bs - 1) // bs * bs
    W = (w + bs - 1) // bs * bs
    pad = np.zeros((H, W), dtype=arr.dtype)
    pad[:h, :w] = arr
    blocks = (pad.reshape(H//bs, bs, W//bs, bs)
                 .transpose(0, 2, 1, 3))  # [nH, nW, 8, 8]
    return blocks, h, w

def _unblockify(blocks: np.ndarray, orig_h: int, orig_w: int):
    nH, nW, bs, _ = blocks.shape
    arr = blocks.transpose(0, 2, 1, 3).reshape(nH*bs, nW*bs)
    return arr[:orig_h, :orig_w]

def _dct2(block):
    return A8 @ block @ A8T

def _idct2(coeff):
    return A8T @ coeff @ A8

def _rgb_to_y(image: Image.Image) -> np.ndarray:
    y, _, _ = image.convert("YCbCr").split()
    return np.array(y, dtype=np.float64)

def _y_to_rgb(y: np.ndarray, base_rgb: Image.Image) -> Image.Image:
    # on remplace le Y de base
    y_img = Image.fromarray(np.clip(y, 0, 255).astype(np.uint8), mode="L")
    Y, Cb, Cr = base_rgb.convert("YCbCr").split()
    out = Image.merge("YCbCr", (y_img, Cb, Cr)).convert("RGB")
    return out

def _quantize(c: np.ndarray, Q: np.ndarray) -> np.ndarray:
    return np.round(c / Q).astype(np.int32)

def _dequantize(qc: np.ndarray, Q: np.ndarray) -> np.ndarray:
    return (qc.astype(np.float64) * Q)

def _bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if bits.size % 8 != 0:
        bits = np.pad(bits, (0, 8 - (bits.size % 8)), constant_values=0)
    return np.packbits(bits).tobytes()

# Header “armored” pour le stego payload
MAGIC = b"EMJPG1"  # 6 bytes
HEADER_FMT = ">6sB16s12sI"   # MAGIC(6) | QUAL(1) | SALT(16) | NONCE(12) | LEN(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 39 bytes

def _build_header(quality: int, salt: bytes, nonce: bytes, payload_len: int) -> bytes:
    q = max(10, min(95, int(quality)))
    return struct.pack(HEADER_FMT, MAGIC, q, salt, nonce, payload_len)

def _parse_header(blob: bytes):
    magic, qual, salt, nonce, payload_len = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError("Invalid JPEG stego header")
    return qual, salt, nonce, payload_len

# ---------- Embedding / Extraction dans les AC ----------
def _embed_bits_in_qcoeff(qblocks: np.ndarray, bits: np.ndarray) -> int:
    """
    qblocks: [nH, nW, 8, 8] int32 (quantized DCT for Y)
    bits   : flat {0,1}
    Retourne: nombre de bits écrits
    """
    nH, nW, _, _ = qblocks.shape
    bit_idx = 0
    for i in range(nH):
        for j in range(nW):
            block = qblocks[i, j]
            # zigzag order
            for k in _MID_AC_IDX:
                if bit_idx >= bits.size:
                    return bit_idx
                u, v = _ZZ[k]
                val = block[u, v]
                if val == 0:
                    continue
                # on évite |val| == 1 (fragile)
                if abs(val) == 1:
                    continue
                b = bits[bit_idx]
                # impose parité sur |val|
                if (abs(val) & 1) != int(b):
                    # ajuste d'une unité vers  +/-
                    if val > 0:
                        val -= 1
                    else:
                        val += 1
                block[u, v] = val
                bit_idx += 1
    return bit_idx

def _extract_bits_from_qcoeff(qblocks: np.ndarray, nbits: int) -> np.ndarray:
    nH, nW, _, _ = qblocks.shape
    out = np.zeros(nbits, dtype=np.uint8)
    bit_idx = 0
    for i in range(nH):
        for j in range(nW):
            block = qblocks[i, j]
            for k in _MID_AC_IDX:
                if bit_idx >= nbits:
                    return out
                u, v = _ZZ[k]
                val = block[u, v]
                if val == 0 or abs(val) == 1:
                    continue
                out[bit_idx] = (abs(val) & 1)
                bit_idx += 1
                if bit_idx >= nbits:
                    return out
    return out

# ---------- ComfyUI Nodes ----------
class Jpeg_Stego_EmbedText:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "text": ("STRING", {"multiline": True, "default": ""}),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
                "quality": ("INT", {"default": 90, "min": 10, "max": 95}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
            }
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("image",)
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, text, passphrase, quality, associated_data=""):
        # 1) PIL
        pil = tensor2pil(image)
        if pil.mode != "RGB":
            pil = pil.convert("RGB")
        # 2) Y channel
        Y = _rgb_to_y(pil).astype(np.float64) - 128.0  # centré
        blocks, h, w = _blockify(Y, 8)
        # 3) DCT + quantization
        Q = _scale_qtable(quality)
        nH, nW, _, _ = blocks.shape
        dct_blocks = np.zeros_like(blocks, dtype=np.float64)
        for i in range(nH):
            for j in range(nW):
                dct_blocks[i, j] = _dct2(blocks[i, j])
        qblocks = _quantize(dct_blocks, Q)

        # 4) payload chiffré
        salt, nonce, cipher = encrypt_bytes(text.encode("utf-8"), passphrase, associated_data)
        header = _build_header(quality, salt, nonce, len(cipher))
        payload = header + cipher
        bits = _bytes_to_bits(payload)

        # 5) embed bits -> qblocks
        written = _embed_bits_in_qcoeff(qblocks, bits)
        if written < bits.size:
            need = bits.size - written
            return (image,)  # capacité insuffisante (on pourrait renvoyer un message d'erreur)

        # 6) dequantize + IDCT
        rec_dct = _dequantize(qblocks, Q)
        rec_blocks = np.zeros_like(rec_dct, dtype=np.float64)
        for i in range(nH):
            for j in range(nW):
                rec_blocks[i, j] = _idct2(rec_dct[i, j])
        Yrec = _unblockify(rec_blocks, h, w) + 128.0

        # 7) remixer en RGB et ré-encoder JPEG (qualité choisie)
        out_rgb = _y_to_rgb(Yrec, pil)
        # on encode en JPEG (qualité), puis on relit -> sortie IMAGE
        buf = io.BytesIO()
        out_rgb.save(buf, format="JPEG", quality=quality, subsampling=1, optimize=False)
        buf.seek(0)
        out_jpeg = Image.open(buf).convert("RGB")
        return pil2tensor(out_jpeg)

class Jpeg_Stego_ExtractText:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, passphrase, associated_data=""):
        pil = tensor2pil(image)
        if pil.mode != "RGB":
            pil = pil.convert("RGB")
        Y = _rgb_to_y(pil).astype(np.float64) - 128.0
        blocks, h, w = _blockify(Y, 8)
        nH, nW, _, _ = blocks.shape

        # Heuristique: essayer qualités communes pour récupérer l'entête
        for try_q in (90, 85, 80, 75):
            Q = _scale_qtable(try_q)
            dct_blocks = np.zeros_like(blocks, dtype=np.float64)
            for i in range(nH):
                for j in range(nW):
                    dct_blocks[i, j] = _dct2(blocks[i, j])
            qblocks = _quantize(dct_blocks, Q)

            # Extraire juste l'entête (39 bytes)
            header_bits = _extract_bits_from_qcoeff(qblocks, HEADER_SIZE * 8)
            header_bytes = _bits_to_bytes(header_bits)[:HEADER_SIZE]
            try:
                qual, salt, nonce, payload_len = _parse_header(header_bytes)
            except Exception:
                continue  # essaie qualité suivante

            # Maintenant extraire header + payload
            total_bits = (HEADER_SIZE + payload_len) * 8
            bits = _extract_bits_from_qcoeff(qblocks, total_bits)
            blob = _bits_to_bytes(bits)[:HEADER_SIZE + payload_len]
            try:
                _, q2, salt2, nonce2, plen2 = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
                if q2 != qual or salt2 != salt or nonce2 != nonce or plen2 != payload_len:
                    continue
            except Exception:
                continue

            cipher = blob[HEADER_SIZE:HEADER_SIZE + payload_len]
            try:
                pt = decrypt_bytes(salt, nonce, cipher, passphrase, associated_data)
                return (pt.decode("utf-8"),)
            except Exception:
                # mauvaise passphrase / mauvais AAD / mauvaise qualité
                continue

        return ("[Jpeg Stego ERROR] Unable to recover payload (quality/transform too strong or wrong passphrase/AAD).",)


NODE_CLASS_MAPPINGS = {
    "Jpeg Stego Embed Text": Jpeg_Stego_EmbedText,
    "Jpeg Stego Extract Text": Jpeg_Stego_ExtractText,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Jpeg Stego Embed Text": "EncryptMaster — Jpeg Stego Embed Text (DCT/AES-GCM)",
    "Jpeg Stego Extract Text": "EncryptMaster — Jpeg Stego Extract Text (DCT/AES-GCM)",
}
