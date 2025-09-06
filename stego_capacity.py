# stego_capacity.py
# EncryptMaster — Stego Capacity Estimator
# Calcule combien d'octets et de caractères max on peut cacher dans une image

import numpy as np
import torch

CATEGORY = "EncryptMaster"

def _capacity_bytes(h: int, w: int, bpc: int) -> int:
    cap_bits = h * w * 3 * bpc
    return cap_bits // 8

class Stego_CapacityEstimator:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
                "bits_per_channel": ([1, 2], {"default": 1}),
            }
        }

    RETURN_TYPES = ("INT", "INT", "STRING")
    RETURN_NAMES = ("capacity_bytes", "capacity_chars", "report")
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(self, image, bits_per_channel):
        # tensor -> shape
        t = image[0].detach().cpu().numpy()  # [H,W,C], float32 [0,1]
        h, w, _ = t.shape
        capacity = _capacity_bytes(h, w, bits_per_channel)

        # réserve 40 octets pour l'entête (salt, nonce, taille…)
        usable_bytes = max(0, capacity - 40)

        # estimation caractères = octets
        usable_chars = usable_bytes

        report = (
            f"Image: {w}x{h}px\n"
            f"Bits per channel: {bits_per_channel}\n"
            f"Capacité totale: {capacity} octets (≈ {capacity/1024:.2f} KiB)\n"
            f"Réservé entête: 40 octets\n"
            f"Utilisable: {usable_bytes} octets ≈ {usable_chars} caractères (UTF-8 simple)\n"
            f"⚠️ Attention: les caractères spéciaux/emoji peuvent prendre plus d’octets."
        )

        return int(capacity), int(usable_chars), report


NODE_CLASS_MAPPINGS = {
    "Stego Capacity Estimator": Stego_CapacityEstimator,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "Stego Capacity Estimator": "EncryptMaster — Stego Capacity Estimator",
}
