# stego_text.py
# EncryptMaster — Stego Text (AES-256-GCM + scrypt + LSB)
# Cache/extrais un texte chiffré dans une image (PNG/TIFF recommandés).
# Nodes :
#   - Stego_EmbedText   : IMAGE, STRING, passphrase -> IMAGE
#   - Stego_ExtractText : IMAGE, passphrase         -> STRING

import os
import struct
from typing import Tuple

import numpy as np
from PIL import Image
import torch

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ===================== Crypto helpers =====================

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
    cipher = aes.encrypt(nonce, plaintext, aad)  # ciphertext || tag
    return salt, nonce, cipher

def decrypt_bytes(salt: bytes, nonce: bytes, cipher: bytes, passphrase: str, associated_data: str = "") -> bytes:
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    aad = associated_data.encode("utf-8") if associated_data else None
    return aes.decrypt(nonce, cipher, aad)


# ===================== Tensor <-> PIL helpers (ComfyUI) =====================

def tensor2pil(img_tensor: torch.Tensor) -> Image.Image:
    """
    img_tensor: torch.Tensor [B,H,W,C] float32 in [0,1]
    -> PIL.Image (RGB/RGBA)
    """
    t = img_tensor[0].detach().cpu()
    arr = t.numpy()
    arr = np.clip(arr, 0.0, 1.0)
    arr = (arr * 255.0).round().astype(np.uint8)

    if arr.ndim == 3 and arr.shape[2] == 4:
        mode = "RGBA"
        return Image.fromarray(arr, mode=mode)
    # force RGB
    if arr.ndim == 2:
        arr = np.stack([arr, arr, arr], axis=-1)
    elif arr.ndim == 3 and arr.shape[2] > 3:
        arr = arr[:, :, :3]
    return Image.fromarray(arr, mode="RGB")

def pil2tensor(img: Image.Image):
    """
    PIL.Image -> (torch.Tensor [B,H,W,C] float32 in [0,1],)
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    arr = np.array(img)
    if arr.ndim == 2:
        arr = np.stack([arr, arr, arr], axis=-1)
    if arr.ndim == 3 and arr.shape[2] == 4:
        # On travaille en RGB pour la stéganographie (3 canaux)
        arr = arr[:, :, :3]
    arr = arr.astype(np.float32) / 255.0
    t = torch.from_numpy(arr).unsqueeze(0)  # [1,H,W,C]
    return (t,)


# ===================== LSB helpers =====================

MAGIC = b"EMSTEG1"  # 7 bytes
# Header: MAGIC(7) | BPC(1) | SALT(16) | NONCE(12) | LEN(4, big-endian)
HEADER_FMT = ">7sB16s12sI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 40 bytes

def _bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if bits.size % 8 != 0:
        bits = np.pad(bits, (0, 8 - (bits.size % 8)), constant_values=0)
    arr = np.packbits(bits)
    return arr.tobytes()

def _capacity_bits(rgb: np.ndarray, bpc: int) -> int:
    h, w, _ = rgb.shape
    return h * w * 3 * bpc

def _embed_bits_into_image(rgb: np.ndarray, bits: np.ndarray, bpc: int) -> np.ndarray:
    """
    rgb: HxWx3 uint8
    bits: flat array of {0,1}
    bpc: 1 or 2
    """
    H, W, _ = rgb.shape
    capacity_bits = _capacity_bits(rgb, bpc)
    if bits.size > capacity_bits:
        raise ValueError(f"Message too large. Capacity={capacity_bits} bits, need={bits.size} bits.")

    flat = rgb.reshape(-1, 3).astype(np.uint8)
    channels = [flat[:, 0], flat[:, 1], flat[:, 2]]

    bit_idx = 0
    mask = 0xFF ^ ((1 << bpc) - 1)  # clear last bpc bits

    for c in range(3):
        ch = channels[c]
        if bit_idx >= bits.size:
            break

        slots = ch.size
        nbits_for_channel = slots * bpc
        take = min(bits.size - bit_idx, nbits_for_channel)

        vals = ch & mask

        if bpc == 1:
            vals[:take] |= bits[bit_idx:bit_idx + take].astype(np.uint8)
            ch[:take] = vals[:take]
            bit_idx += take
        else:  # bpc == 2
            # nombre de paires (2 bits)
            pairs = take // 2
            if pairs > 0:
                b = bits[bit_idx:bit_idx + pairs * 2].reshape(-1, 2)
                twob = (b[:, 0].astype(np.uint8) << 1) | b[:, 1].astype(np.uint8)
                vals[:pairs] |= twob
                ch[:pairs] = vals[:pairs]
                bit_idx += pairs * 2

        channels[c] = ch

    out = np.stack(channels, axis=1).reshape(H, W, 3)
    return out

def _extract_bits_from_image(rgb: np.ndarray, nbits: int, bpc: int) -> np.ndarray:
    H, W, _ = rgb.shape
    capacity_bits = _capacity_bits(rgb, bpc)
    if nbits > capacity_bits:
        raise ValueError("Requested more bits than image capacity.")

    flat = rgb.reshape(-1, 3).astype(np.uint8)
    channels = [flat[:, 0], flat[:, 1], flat[:, 2]]

    out_bits = np.zeros(nbits, dtype=np.uint8)
    bit_idx = 0

    for c in range(3):
        ch = channels[c]
        if bit_idx >= nbits:
            break

        if bpc == 1:
            take = min(nbits - bit_idx, ch.size)
            out_bits[bit_idx:bit_idx + take] = (ch[:take] & 0x01).astype(np.uint8)
            bit_idx += take
        else:  # 2 bits
            remaining = nbits - bit_idx
            pairs = min(ch.size, (remaining + 1) // 2)
            if pairs <= 0:
                continue
            vals = ch[:pairs] & 0x03
            b1 = (vals >> 1) & 1
            b2 = vals & 1
            merged = np.column_stack([b1, b2]).reshape(-1)
            take = min(remaining, merged.size)
            out_bits[bit_idx:bit_idx + take] = merged[:take]
            bit_idx += take

    return out_bits

def _build_header_bytes(bpc: int, salt: bytes, nonce: bytes, payload_len: int) -> bytes:
    return struct.pack(HEADER_FMT, MAGIC, bpc, salt, nonce, payload_len)

def _read_header(rgb: np.ndarray, bpc_hint: int = 1) -> Tuple[int, bytes, bytes, int]:
    """
    Lit l'entête (40 octets) et renvoie (bpc, salt, nonce, payload_len)
    Essaie avec bpc=1 puis bpc=2 si nécessaire.
    """
    def try_read(bpc):
        bits_needed = HEADER_SIZE * 8
        bits = _extract_bits_from_image(rgb, bits_needed, bpc)
        header_bytes = _bits_to_bytes(bits)[:HEADER_SIZE]
        magic, bpc_enc, salt, nonce, payload_len = struct.unpack(HEADER_FMT, header_bytes)
        if magic != MAGIC:
            raise ValueError("Invalid magic header")
        if bpc_enc not in (1, 2):
            raise ValueError("Invalid bpc in header")
        return bpc_enc, salt, nonce, payload_len

    try:
        return try_read(1)
    except Exception:
        return try_read(2)


# ===================== ComfyUI Nodes =====================

CATEGORY = "EncryptMaster"

class Stego_EmbedText:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "text": ("STRING", {"multiline": True, "default": ""}),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
                "bits_per_channel": ([1, 2], {"default": 1}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
            },
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("image",)
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, text, passphrase, bits_per_channel, associated_data=""):
        if bits_per_channel not in (1, 2):
            return (image,)

        # tensor -> PIL -> np RGB
        pil = tensor2pil(image)
        if pil.mode != "RGB":
            pil = pil.convert("RGB")
        rgb = np.array(pil, dtype=np.uint8)

        # chiffrer le texte
        plaintext = text.encode("utf-8")
        salt, nonce, cipher = encrypt_bytes(plaintext, passphrase, associated_data)

        header = _build_header_bytes(bits_per_channel, salt, nonce, len(cipher))
        payload = header + cipher
        bits = _bytes_to_bits(payload)

        # capacité
        cap_bits = _capacity_bits(rgb, bits_per_channel)
        if bits.size > cap_bits:
            need_bytes = (bits.size + 7) // 8
            have_bytes = cap_bits // 8
            return (tensor2pil(image),) if False else (  # dead code to keep type
                pil2tensor(pil)[0],
            )  # pragma: no cover

        rgb_stego = _embed_bits_into_image(rgb, bits, bits_per_channel)
        out = Image.fromarray(rgb_stego, mode="RGB")
        return pil2tensor(out)


class Stego_ExtractText:
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

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, passphrase, associated_data=""):
        pil = tensor2pil(image)
        if pil.mode != "RGB":
            pil = pil.convert("RGB")
        rgb = np.array(pil, dtype=np.uint8)

        try:
            bpc, salt, nonce, payload_len = _read_header(rgb)
        except Exception as e:
            return (f"[Stego ERROR] {type(e).__name__}: {e}",)

        total_bits = (HEADER_SIZE + payload_len) * 8
        try:
            bits = _extract_bits_from_image(rgb, total_bits, bpc)
        except Exception as e:
            return (f"[Stego ERROR] {type(e).__name__}: {e}",)

        blob = _bits_to_bytes(bits)[: HEADER_SIZE + payload_len]
        try:
            magic, bpc_enc, salt2, nonce2, payload_len2 = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
            if magic != MAGIC or salt2 != salt or nonce2 != nonce or payload_len2 != payload_len:
                return ("[Stego ERROR] Header mismatch",)
        except Exception as e:
            return (f"[Stego ERROR] {type(e).__name__}: {e}",)

        cipher = blob[HEADER_SIZE : HEADER_SIZE + payload_len]
        try:
            pt = decrypt_bytes(salt, nonce, cipher, passphrase, associated_data)
            return (pt.decode("utf-8"),)
        except Exception as e:
            return (f"[Stego ERROR] {type(e).__name__}: {e}",)


# ===================== ComfyUI mappings =====================

NODE_CLASS_MAPPINGS = {
    "Stego Embed Text": Stego_EmbedText,
    "Stego Extract Text": Stego_ExtractText,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Stego Embed Text": "EncryptMaster — Stego Embed Text (AES-GCM)",
    "Stego Extract Text": "EncryptMaster — Stego Extract Text (AES-GCM)",
}
