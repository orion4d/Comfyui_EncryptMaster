# -*- coding: utf-8 -*-
# ComfyUI_EncryptMaster / __init__.py

NODE_ID = "EncryptMaster"

from .text_cipher import TextCipher
from .stego_text import Stego_EmbedText as StegoEmbedText, Stego_ExtractText as StegoExtractText
from .generate_passphrase import GeneratePassphrase
from .stego_capacity import Stego_CapacityEstimator
from .image_cipher import Image_CipherToNoise, Image_DecipherFromNoise
from .jpeg_stego import Jpeg_Stego_EmbedText, Jpeg_Stego_ExtractText
from .stego_image_in_image import Stego_EmbedImage, Stego_ExtractImage

# Dictionnaires de mapping
NODE_CLASS_MAPPINGS = {
    "Text Cipher": TextCipher,
    "Stego Embed Text": StegoEmbedText,
    "Stego Extract Text": StegoExtractText,
    "Generate Passphrase": GeneratePassphrase,
    "Stego Capacity Estimator": Stego_CapacityEstimator,
    "Image Cipher To Noise": Image_CipherToNoise,
    "Image Decipher From Noise": Image_DecipherFromNoise,
    "Jpeg Stego Embed Text": Jpeg_Stego_EmbedText,
    "Jpeg Stego Extract Text": Jpeg_Stego_ExtractText,
    "Stego Embed Image": Stego_EmbedImage,
    "Stego Extract Image": Stego_ExtractImage,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Text Cipher": "EncryptMaster — Text Cipher (AES-GCM)",
    "Stego Embed Text": "EncryptMaster — Stego Embed Text (AES-GCM)",
    "Stego Extract Text": "EncryptMaster — Stego Extract Text (AES-GCM)",
    "Generate Passphrase": "EncryptMaster — Generate Passphrase",
    "Stego Capacity Estimator": "EncryptMaster — Stego Capacity Estimator",
    "Image Cipher To Noise": "EncryptMaster — Image Cipher → Noise (AES-GCM)",
    "Image Decipher From Noise": "EncryptMaster — Image Decipher ← Noise (AES-GCM)",
    "Jpeg Stego Embed Text": "EncryptMaster — Jpeg Stego Embed Text (DCT/AES-GCM)",
    "Jpeg Stego Extract Text": "EncryptMaster — Jpeg Stego Extract Text (DCT/AES-GCM)",
    "Stego Embed Image": "EncryptMaster — Stego Embed Image (LSB/AES-GCM)",
    "Stego Extract Image": "EncryptMaster — Stego Extract Image (LSB/AES-GCM)",
}

WEB_DIRECTORY = "./web"

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY"]

print(f"### Loading: {NODE_ID}")
print(f"    - Mapped {len(NODE_CLASS_MAPPINGS)} nodes")
