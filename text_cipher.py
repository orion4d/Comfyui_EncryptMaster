# text_cipher.py
# Text Cipher (AES-256-GCM + scrypt)
#
# Entrées:
#   - text (STRING, multiline) : texte en clair OU chaîne chiffrée "armored"
#   - passphrase (STRING, password) : mot de passe humain
#   - mode ("encrypt" | "decrypt")
#   - associated_data (STRING, optionnel) : métadonnées authentifiées (AEAD)
#
# Sorties:
#   - text (STRING) : si mode=encrypt => chaîne chiffrée "armored"
#                     si mode=decrypt => texte en clair
#
# Dépendance : pip install cryptography

import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CATEGORY = "EncryptMaster"
DISPLAY_NAME = "Text Cipher (AES-GCM)"
NODE_NAME = "TextCipher"

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64d(s: str) -> bytes:
    # Supporte base64 urlsafe sans padding
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    # scrypt parameters: N=2^14, r=8, p=1 (bon équilibre sécurité/perf CPU)
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def _encrypt(plaintext: str, passphrase: str, associated_data: str = "") -> str:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    if not passphrase:
        raise ValueError("passphrase cannot be empty")

    salt = os.urandom(16)     # pour KDF scrypt
    key = _derive_key(passphrase, salt)  # 32 bytes
    aes = AESGCM(key)
    nonce = os.urandom(12)    # requis par AES-GCM
    aad = associated_data.encode("utf-8") if associated_data else None
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), aad)
    # Format “armored”
    return f"aesgcm-scrypt.v1${_b64e(salt)}${_b64e(nonce)}${_b64e(ct)}"

def _parse_armored(armored: str) -> Tuple[bytes, bytes, bytes]:
    # aesgcm-scrypt.v1$<salt>$<nonce>$<cipher>
    parts = armored.split("$")
    if len(parts) != 4 or parts[0] != "aesgcm-scrypt.v1":
        raise ValueError("Invalid armored format or version.")
    salt = _b64d(parts[1])
    nonce = _b64d(parts[2])
    cipher = _b64d(parts[3])
    if len(salt) < 16 or len(nonce) != 12:
        raise ValueError("Invalid salt/nonce length.")
    return salt, nonce, cipher

def _decrypt(armored: str, passphrase: str, associated_data: str = "") -> str:
    if not isinstance(armored, str):
        raise TypeError("ciphertext must be str")
    if not passphrase:
        raise ValueError("passphrase cannot be empty")

    salt, nonce, cipher = _parse_armored(armored)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    aad = associated_data.encode("utf-8") if associated_data else None
    pt = aes.decrypt(nonce, cipher, aad)
    return pt.decode("utf-8")


class TextCipher:
    """
    Un node ComfyUI simple pour chiffrer/déchiffrer du texte avec AES-256-GCM
    et dérivation de clé via scrypt. Compatible “list mapping” (STRING).
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "text": ("STRING", {"multiline": True, "default": ""}),
                "passphrase": ("STRING", {"multiline": False, "default": "", "password": True}),
                "mode": (["encrypt", "decrypt"], {"default": "encrypt"}),
            },
            "optional": {
                "associated_data": ("STRING", {"multiline": False, "default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, text: str, passphrase: str, mode: str, associated_data: str = ""):
        try:
            if mode == "encrypt":
                out = _encrypt(text, passphrase, associated_data)
            else:
                out = _decrypt(text, passphrase, associated_data)
            return (out,)
        except Exception as e:
            # Retourne l'erreur en clair (option pragmatique pour debug workflow)
            return (f"[TextCipher ERROR] {type(e).__name__}: {e}",)


# Mappings pour ComfyUI
NODE_CLASS_MAPPINGS = {
    NODE_NAME: TextCipher,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    NODE_NAME: DISPLAY_NAME,
}
