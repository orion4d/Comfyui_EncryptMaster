# image_cipher.py
# EncryptMaster — Image <-> Noise (AES-256-GCM + scrypt)
# - Image_CipherToNoise   : chiffre une image en "bruit" (PNG/TIFF conseillé)
# - Image_DecipherFromNoise : reconstruit l'image originale depuis le "bruit"
#
# Remarques:
# - La sortie peut être +haute que l'entrée (quelques lignes) pour stocker l'overhead (sel+nonce+header+tag).
# - Sauvegarder en PNG/TIFF (sans perte). Le JPEG casserait les octets.

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

# ======== Crypto helpers ========
def _derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    if not passphrase:
        raise ValueError("passphrase cannot be empty")
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def _encrypt(plaintext: bytes, passphrase: str, aad: str = "") -> Tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ad = aad.encode("utf-8") if aad else None
    cipher = aes.encrypt(nonce, plaintext, ad)  # = plaintext + 16-byte tag
    return salt, nonce, cipher

def _decrypt(salt: bytes, nonce: bytes, cipher: bytes, passphrase: str, aad: str = "") -> bytes:
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    ad = aad.encode("utf-8") if aad else None
    return aes.decrypt(nonce, cipher, ad)

# ======== Tensor <-> PIL helpers ========
def tensor2rgb_u8(img_tensor: torch.Tensor) -> np.ndarray:
    """
    torch.Tensor [B,H,W,C] float32 in [0,1] -> np.uint8 [H,W,3]
    """
    t = img_tensor[0].detach().cpu().numpy()  # [H,W,C]
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
    """
    np.uint8 [H,W,3] -> (torch.Tensor [B,H,W,C] float32 in [0,1],)
    """
    arr = arr.astype(np.float32) / 255.0
    t = torch.from_numpy(arr).unsqueeze(0)
    return (t,)

# ======== Payload header ========
# MAGIC(6) | VER(1) | H(4) | W(4) | C(1) | CIPHER_LEN(8) | RSRV(4)
# = 6 + 1 + 4 + 4 + 1 + 8 + 4 = 28 bytes
MAGIC = b"EMIMG1"
HEADER_FMT = ">6sBIIBQ I"  # Espace ignoré par struct; équiv. ">6sBII BQI"
# Pour éviter toute ambiguïté, on calcule la taille explicitement:
HEADER_SIZE = 6 + 1 + 4 + 4 + 1 + 8 + 4  # 28

def _build_header(h: int, w: int, c: int, cipher_len: int, ver: int = 1) -> bytes:
    # RSRV = 0 (réservé pour futures versions)
    # Comme struct ne gère pas bien les espaces dans le fmt, pack manuellement:
    return (
        MAGIC
        + bytes([ver & 0xFF])
        + struct.pack(">I", h)
        + struct.pack(">I", w)
        + bytes([c & 0xFF])
        + struct.pack(">Q", cipher_len)
        + struct.pack(">I", 0)
    )

def _parse_header(buf: bytes):
    if len(buf) < HEADER_SIZE:
        raise ValueError("Header too small")
    if buf[:6] != MAGIC:
        raise ValueError("Invalid magic")
    ver = buf[6]
    h = struct.unpack(">I", buf[7:11])[0]
    w = struct.unpack(">I", buf[11:15])[0]
    c = buf[15]
    cipher_len = struct.unpack(">Q", buf[16:24])[0]
    # rsrv = struct.unpack(">I", buf[24:28])[0]
    return ver, h, w, c, cipher_len

# ======== Nodes ========
class Image_CipherToNoise:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
                "preserve_width": ("BOOLEAN", {"default": True}),
            },
        }

    RETURN_TYPES = ("IMAGE", "INT", "INT")
    RETURN_NAMES = ("image", "out_width", "out_height")
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, passphrase, associated_data="", preserve_width=True):
        # 1) Image -> bytes
        rgb = tensor2rgb_u8(image)  # [H,W,3]
        h, w, c = rgb.shape
        plain = rgb.tobytes(order="C")  # len = h*w*3

        # 2) Encrypt
        salt, nonce, cipher = _encrypt(plain, passphrase, associated_data)

        # 3) Build payload: header + salt + nonce + cipher
        header = _build_header(h, w, 3, len(cipher), ver=1)
        payload = header + salt + nonce + cipher
        total = len(payload)

        # 4) Decide output size (capacity = H*W*3 bytes). We enlarge height if needed.
        if preserve_width and w > 0:
            out_w = w
            pixels = math.ceil(total / 3)
            out_h = math.ceil(pixels / out_w)
        else:
            # make it near-square if free width
            pixels = math.ceil(total / 3)
            side = int(math.sqrt(pixels))
            out_w = max(1, side)
            out_h = math.ceil(pixels / out_w)

        # 5) Fill noise buffer
        out = np.frombuffer(os.urandom(out_w * out_h * 3), dtype=np.uint8).copy()
        out[:total] = np.frombuffer(payload, dtype=np.uint8)
        out = out.reshape(out_h, out_w, 3)

        return rgb_u8_to_tensor(out) + (int(out_w), int(out_h))


class Image_DecipherFromNoise:
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
        # 1) Read raw bytes from noise image
        arr = tensor2rgb_u8(image)  # [H,W,3]
        raw = arr.reshape(-1).tobytes(order="C")

        # 2) Parse header
        if len(raw) < HEADER_SIZE + 16 + 12:
            return (rgb_u8_to_tensor(np.zeros((1,1,3), dtype=np.uint8))[0],
                    "[ImageCipher ERROR] Not enough data for header")
        ver, orig_h, orig_w, orig_c, cipher_len = _parse_header(raw[:HEADER_SIZE])

        # 3) Read salt, nonce, cipher
        ofs = HEADER_SIZE
        salt = raw[ofs:ofs+16]; ofs += 16
        nonce = raw[ofs:ofs+12]; ofs += 12
        end = ofs + cipher_len
        if end > len(raw):
            return (rgb_u8_to_tensor(np.zeros((1,1,3), dtype=np.uint8))[0],
                    "[ImageCipher ERROR] Truncated payload")
        cipher = raw[ofs:end]

        # 4) Decrypt
        try:
            plain = _decrypt(salt, nonce, cipher, passphrase, associated_data)
        except Exception as e:
            return (rgb_u8_to_tensor(np.zeros((1,1,3), dtype=np.uint8))[0],
                    f"[ImageCipher ERROR] {type(e).__name__}: {e}")

        # 5) Rebuild original image
        needed = orig_h * orig_w * orig_c
        if len(plain) != needed or orig_c != 3:
            return (rgb_u8_to_tensor(np.zeros((1,1,3), dtype=np.uint8))[0],
                    "[ImageCipher ERROR] Invalid plaintext size/channels")
        rgb = np.frombuffer(plain, dtype=np.uint8).reshape(orig_h, orig_w, 3)
        return rgb_u8_to_tensor(rgb)[0], f"Recovered {orig_w}x{orig_h} RGB image (v{ver})."


# ======== ComfyUI mappings ========
NODE_CLASS_MAPPINGS = {
    "Image Cipher To Noise": Image_CipherToNoise,
    "Image Decipher From Noise": Image_DecipherFromNoise,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Image Cipher To Noise": "EncryptMaster — Image Cipher → Noise (AES-GCM)",
    "Image Decipher From Noise": "EncryptMaster — Image Decipher ← Noise (AES-GCM)",
}
