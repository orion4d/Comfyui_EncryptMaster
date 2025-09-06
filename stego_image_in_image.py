# stego_image_in_image.py
# EncryptMaster — Stego Image-in-Image (AES-256-GCM + scrypt + LSB)
# Cache une image "secrète" dans une image "porteuse" (PNG/TIFF recommandé).
# Améliorations :
#  - Quand resize_secret_to_cover=True, on chiffre la version redimensionnée (fix).
#  - secret_encode: "png" (defaut) ou "jpeg" (avec jpeg_quality) -> compression AVANT chiffrement.
#  - Header inclut le "enc_type" (0=raw, 1=png, 2=jpeg).

import io
import os
import struct
from typing import Tuple

import numpy as np
from PIL import Image
import torch
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CATEGORY = "EncryptMaster"

# ========= Crypto =========
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

# ========= Tensor <-> RGB uint8 =========
def tensor2rgb_u8(img_tensor: torch.Tensor) -> np.ndarray:
    t = img_tensor[0].detach().cpu().numpy()
    t = np.clip(t, 0.0, 1.0)
    arr = (t * 255.0).round().astype(np.uint8)
    if arr.ndim == 2:
        arr = np.stack([arr, arr, arr], axis=-1)
    if arr.shape[2] < 3:
        arr = np.tile(arr[:, :, :1], (1, 1, 3))
    if arr.shape[2] > 3:
        arr = arr[:, :, :3]
    return arr

def rgb_u8_to_tensor(arr: np.ndarray):
    arr = arr.astype(np.float32) / 255.0
    t = torch.from_numpy(arr).unsqueeze(0)
    return (t,)

# ========= LSB helpers =========
MAGIC = b"EMIIMG2"  # 7 bytes (v2 header)

# Header v2 (50 octets):
# 0..6   MAGIC (7)
# 7      BPC   (1)
# 8..11  SH    (4, >I)
# 12..15 SW    (4, >I)
# 16     SC    (1)  (toujours 3 = RGB après décodage)
# 17     ENC   (1)  (0=raw, 1=png, 2=jpeg)
# 18..33 SALT  (16)
# 34..45 NONCE (12)
# 46..49 LEN   (4, >I)
HEADER_SIZE = 50

def _bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if bits.size % 8 != 0:
        bits = np.pad(bits, (0, 8 - (bits.size % 8)), constant_values=0)
    return np.packbits(bits).tobytes()

def _capacity_bits(rgb: np.ndarray, bpc: int) -> int:
    h, w, _ = rgb.shape
    return h * w * 3 * bpc

def _embed_bits_into_image(rgb: np.ndarray, bits: np.ndarray, bpc: int) -> np.ndarray:
    H, W, _ = rgb.shape
    cap = _capacity_bits(rgb, bpc)
    if bits.size > cap:
        raise ValueError(f"Message too large. Capacity={cap} bits, need={bits.size} bits.")

    flat = rgb.reshape(-1, 3).astype(np.uint8)
    channels = [flat[:, 0], flat[:, 1], flat[:, 2]]
    bit_idx = 0
    mask = 0xFF ^ ((1 << bpc) - 1)

    for c in range(3):
        ch = channels[c]
        if bpc == 1:
            take = min(bits.size - bit_idx, ch.size)
            if take > 0:
                vals = ch & mask
                vals[:take] |= bits[bit_idx:bit_idx + take].astype(np.uint8)
                ch[:take] = vals[:take]
                bit_idx += take
        else:
            remaining = bits.size - bit_idx
            pairs = min(ch.size, remaining // 2)
            if pairs > 0:
                vals = ch & mask
                b = bits[bit_idx:bit_idx + pairs * 2].reshape(-1, 2)
                twob = (b[:, 0].astype(np.uint8) << 1) | b[:, 1].astype(np.uint8)
                vals[:pairs] |= twob
                ch[:pairs] = vals[:pairs]
                bit_idx += pairs * 2
        channels[c] = ch
        if bit_idx >= bits.size:
            break

    out = np.stack(channels, axis=1).reshape(H, W, 3)
    return out

def _extract_bits_from_image(rgb: np.ndarray, nbits: int, bpc: int) -> np.ndarray:
    H, W, _ = rgb.shape
    cap = _capacity_bits(rgb, bpc)
    if nbits > cap:
        raise ValueError("Requested more bits than image capacity.")

    flat = rgb.reshape(-1, 3).astype(np.uint8)
    channels = [flat[:, 0], flat[:, 1], flat[:, 2]]
    out_bits = np.zeros(nbits, dtype=np.uint8)
    bit_idx = 0

    for c in range(3):
        ch = channels[c]
        if bpc == 1:
            take = min(nbits - bit_idx, ch.size)
            if take > 0:
                out_bits[bit_idx:bit_idx + take] = (ch[:take] & 0x01).astype(np.uint8)
                bit_idx += take
        else:
            remaining = nbits - bit_idx
            pairs = min(ch.size, (remaining + 1) // 2)
            if pairs > 0:
                vals = ch[:pairs] & 0x03
                b1 = (vals >> 1) & 1
                b2 = vals & 1
                merged = np.column_stack([b1, b2]).reshape(-1)
                take = min(remaining, merged.size)
                out_bits[bit_idx:bit_idx + take] = merged[:take]
                bit_idx += take
        if bit_idx >= nbits:
            break
    return out_bits

def _build_header(bpc: int, sh: int, sw: int, sc: int, enc_type: int, salt: bytes, nonce: bytes, payload_len: int) -> bytes:
    return (
        MAGIC +
        bytes([bpc & 0xFF]) +
        struct.pack(">I", sh) +
        struct.pack(">I", sw) +
        bytes([sc & 0xFF]) +
        bytes([enc_type & 0xFF]) +
        salt +
        nonce +
        struct.pack(">I", payload_len)
    )

def _parse_header_bytes(hb: bytes):
    if len(hb) < HEADER_SIZE:
        raise ValueError("Header too small")
    if hb[:7] != MAGIC:
        raise ValueError("Invalid magic")
    bpc = hb[7]
    sh = struct.unpack(">I", hb[8:12])[0]
    sw = struct.unpack(">I", hb[12:16])[0]
    sc = hb[16]
    enc_type = hb[17]
    salt = hb[18:34]
    nonce = hb[34:46]
    payload_len = struct.unpack(">I", hb[46:50])[0]
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Invalid salt/nonce length")
    return bpc, sh, sw, sc, enc_type, salt, nonce, payload_len

def _read_header(rgb: np.ndarray):
    for bpc_try in (1, 2):
        bits = _extract_bits_from_image(rgb, HEADER_SIZE * 8, bpc_try)
        hb = _bits_to_bytes(bits)[:HEADER_SIZE]
        try:
            return _parse_header_bytes(hb)
        except Exception:
            continue
    raise ValueError("Header not found")

# ========= Nodes =========
class Stego_EmbedImage:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "cover_image": ("IMAGE",),
                "secret_image": ("IMAGE",),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
                "bits_per_channel": ([1, 2], {"default": 1}),
                "secret_encode": (["png", "jpeg"], {"default": "png"}),
            },
            "optional": {
                "jpeg_quality": ("INT", {"default": 85, "min": 50, "max": 95}),
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
                "resize_secret_to_cover": ("BOOLEAN", {"default": True}),
            },
        }

    RETURN_TYPES = ("IMAGE", "STRING")
    RETURN_NAMES = ("image", "report")
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, cover_image, secret_image, passphrase, bits_per_channel,
            secret_encode, jpeg_quality=85, associated_data="", resize_secret_to_cover=True):

        if bits_per_channel not in (1, 2):
            bits_per_channel = 1

        cover = tensor2rgb_u8(cover_image)

        # --- préparer l'image secrète (et VRAIMENT la redimensionner si demandé) ---
        secret_arr = tensor2rgb_u8(secret_image)
        if resize_secret_to_cover:
            sw, sh = cover.shape[1], cover.shape[0]
            secret_pil = Image.fromarray(secret_arr, mode="RGB").resize((sw, sh), Image.LANCZOS)
        else:
            sh, sw, _ = secret_arr.shape
            secret_pil = Image.fromarray(secret_arr, mode="RGB")

        # --- encodage (compression) avant chiffrement ---
        enc_type = 1 if secret_encode == "png" else 2  # 0=raw,1=png,2=jpeg
        if enc_type == 1:  # PNG
            buf = io.BytesIO()
            # PNG lossless -> peut faire 100–1500 Ko selon contenu
            secret_pil.save(buf, format="PNG", optimize=True, compress_level=6)
            plaintext = buf.getvalue()
        elif enc_type == 2:  # JPEG
            buf = io.BytesIO()
            # JPEG q85 -> ~200–400 Ko sur 1216x1600 typique
            secret_pil.save(buf, format="JPEG", quality=int(jpeg_quality), subsampling=1, optimize=True)
            plaintext = buf.getvalue()
        else:  # raw (rarement utile)
            plaintext = np.array(secret_pil, dtype=np.uint8).tobytes(order="C")
            enc_type = 0

        salt, nonce, cipher = encrypt_bytes(plaintext, passphrase, associated_data)

        header = _build_header(bits_per_channel, sh, sw, 3, enc_type, salt, nonce, len(cipher))
        payload = header + cipher
        bits = _bytes_to_bits(payload)

        cap_bits = _capacity_bits(cover, bits_per_channel)
        if bits.size > cap_bits:
            need_bytes = (bits.size + 7) // 8
            have_bytes = cap_bits // 8
            msg = (f"[StegoImage ERROR] Capacity too small: need ~{need_bytes} bytes, have ~{have_bytes} bytes. "
                   f"Tip: use secret_encode='jpeg' (q={jpeg_quality}) ou une cover plus grande / bpc=2.")
            return rgb_u8_to_tensor(cover)[0], msg

        stego = _embed_bits_into_image(cover, bits, bits_per_channel)
        return rgb_u8_to_tensor(stego)[0], f"Embedded secret {sw}x{sh} enc={secret_encode} bpc={bits_per_channel}"

class Stego_ExtractImage:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
            },
        }

    RETURN_TYPES = ("IMAGE", "STRING")
    RETURN_NAMES = ("image", "report")
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, passphrase, associated_data=""):
        cover = tensor2rgb_u8(image)
        try:
            bpc_enc, sh, sw, sc, enc_type, salt, nonce, payload_len = _read_header(cover)
        except Exception as e:
            tiny = np.zeros((1,1,3), dtype=np.uint8)
            return rgb_u8_to_tensor(tiny)[0], f"[StegoImage ERROR] {type(e).__name__}: {e}"

        total_bits = (HEADER_SIZE + payload_len) * 8
        try:
            bits = _extract_bits_from_image(cover, total_bits, int(bpc_enc))
        except Exception as e:
            tiny = np.zeros((1,1,3), dtype=np.uint8)
            return rgb_u8_to_tensor(tiny)[0], f"[StegoImage ERROR] {type(e).__name__}: {e}"

        blob = _bits_to_bytes(bits)[:HEADER_SIZE + payload_len]
        try:
            bpc2, sh2, sw2, sc2, enc2, salt2, nonce2, len2 = _parse_header_bytes(blob[:HEADER_SIZE])
            if not (bpc2 == bpc_enc and sh2 == sh and sw2 == sw and sc2 == sc and enc2 == enc_type and salt2 == salt and nonce2 == nonce and len2 == payload_len):
                tiny = np.zeros((1,1,3), dtype=np.uint8)
                return rgb_u8_to_tensor(tiny)[0], "[StegoImage ERROR] Header mismatch"
        except Exception as e:
            tiny = np.zeros((1,1,3), dtype=np.uint8)
            return rgb_u8_to_tensor(tiny)[0], f"[StegoImage ERROR] {type(e).__name__}: {e}"

        cipher = blob[HEADER_SIZE:HEADER_SIZE + payload_len]
        try:
            plaintext = decrypt_bytes(salt, nonce, cipher, passphrase, associated_data)
        except Exception as e:
            tiny = np.zeros((1,1,3), dtype=np.uint8)
            return rgb_u8_to_tensor(tiny)[0], f"[StegoImage ERROR] {type(e).__name__}: {e}"

        # décodage selon enc_type
        if enc_type == 0:
            # raw RGB
            if len(plaintext) != sh * sw * 3:
                tiny = np.zeros((1,1,3), dtype=np.uint8)
                return rgb_u8_to_tensor(tiny)[0], "[StegoImage ERROR] Invalid raw size"
            secret = np.frombuffer(plaintext, dtype=np.uint8).reshape(sh, sw, 3)
        else:
            try:
                img = Image.open(io.BytesIO(plaintext)).convert("RGB")
                secret = np.array(img, dtype=np.uint8)
            except Exception as e:
                tiny = np.zeros((1,1,3), dtype=np.uint8)
                return rgb_u8_to_tensor(tiny)[0], f"[StegoImage ERROR] Decode failed: {type(e).__name__}"
        return rgb_u8_to_tensor(secret)[0], f"Recovered secret {secret.shape[1]}x{secret.shape[0]} (enc={'png' if enc_type==1 else 'jpeg' if enc_type==2 else 'raw'})"
        

# ========= ComfyUI mappings =========
NODE_CLASS_MAPPINGS = {
    "Stego Embed Image": Stego_EmbedImage,
    "Stego Extract Image": Stego_ExtractImage,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Stego Embed Image": "EncryptMaster — Stego Embed Image (LSB/AES-GCM)",
    "Stego Extract Image": "EncryptMaster — Stego Extract Image (LSB/AES-GCM)",
}
