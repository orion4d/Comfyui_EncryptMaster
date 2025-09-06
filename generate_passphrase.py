# generate_passphrase.py
# Generate Passphrase
# Deux modes: random_chars (cryptographique) et diceware (wordlist externe)
#
# Entrées (random_chars):
#   length:int, use_lowercase:bool, use_uppercase:bool, use_digits:bool, use_symbols:bool,
#   exclude_ambiguous:bool, extra_digits_suffix:int (0..6), deterministic_seed:int (=-1 pour off)
#
# Entrées (diceware):
#   diceware_wordlist_path:str, num_words:int, separator:str, extra_digits_suffix:int,
#   deterministic_seed:int (=-1 pour off)
#
# Sorties:
#   passphrase: STRING
#   entropy_bits: FLOAT
#   recipe: STRING
#
# Notes:
# - RNG par defaut: secrets (cryptographiquement sûr)
# - Si deterministic_seed >= 0: bascule sur random.Random(seed) (DEV UNIQUEMENT)

import os
import math
import string
import random
from typing import List, Tuple

try:
    import secrets
    _HAS_SECRETS = True
except Exception:
    _HAS_SECRETS = False

CATEGORY = "EncryptMaster"

AMBIGUOUS = set("Il1O0oB8S5Z2")
SYMBOLS_DEFAULT = "!@#$%^&*()_-+=[]{};:,.?/\\|~`"

def _safe_choice(seq, rng_secrets: bool, rnd: random.Random | None):
    if rng_secrets and _HAS_SECRETS:
        return secrets.choice(seq)
    return rnd.choice(seq)  # type: ignore

def _safe_randint(a: int, b: int, rng_secrets: bool, rnd: random.Random | None) -> int:
    if rng_secrets and _HAS_SECRETS:
        # secrets.randbelow pour bornes inclusives
        return a + secrets.randbelow(b - a + 1)
    return rnd.randint(a, b)  # type: ignore

def _build_charset(use_lowercase: bool, use_uppercase: bool, use_digits: bool, use_symbols: bool, exclude_ambiguous: bool) -> List[str]:
    pool = ""
    if use_lowercase:
        pool += string.ascii_lowercase
    if use_uppercase:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += SYMBOLS_DEFAULT

    if exclude_ambiguous:
        pool = "".join([c for c in pool if c not in AMBIGUOUS])

    # sécurité: éviter pool vide
    if not pool:
        # minimal fallback : minuscules
        pool = string.ascii_lowercase
    return list(pool)

def _entropy_random_chars(length: int, alphabet_size: int, extra_digits_suffix: int) -> float:
    # H = length*log2(S) + extra_digits_suffix*log2(10)
    return length * math.log2(max(2, alphabet_size)) + extra_digits_suffix * math.log2(10)

def _entropy_diceware(num_words: int, vocab_size: int, extra_digits_suffix: int) -> float:
    # H = num_words*log2(vocab_size) + extra_digits_suffix*log2(10)
    return num_words * math.log2(max(2, vocab_size)) + extra_digits_suffix * math.log2(10)

def _load_wordlist(path: str) -> List[str]:
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Diceware wordlist not found: {path}")
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
    # éviter doublons vides
    words = [w for w in words if w]
    if len(words) < 1000:
        # 1000+ recommandé pour une entropie correcte
        raise ValueError(f"Wordlist too small ({len(words)} entries). Provide a larger list (e.g., 2048–7776+).")
    return words

def _gen_random_chars(length: int, charset: List[str], extra_digits_suffix: int, rng_secrets: bool, rnd: random.Random | None) -> str:
    # assure au moins 1 caractère de chaque classe activée ? Non: on laisse aléatoire pur (entropie max)
    out = "".join(_safe_choice(charset, rng_secrets, rnd) for _ in range(max(1, length)))
    if extra_digits_suffix > 0:
        digits = "".join(str(_safe_randint(0, 9, rng_secrets, rnd)) for _ in range(extra_digits_suffix))
        out = out + digits
    return out

def _gen_diceware(num_words: int, words: List[str], separator: str, extra_digits_suffix: int, rng_secrets: bool, rnd: random.Random | None) -> str:
    picks = []
    for _ in range(max(1, num_words)):
        if rng_secrets and _HAS_SECRETS:
            idx = secrets.randbelow(len(words))
        else:
            idx = rnd.randrange(len(words))  # type: ignore
        picks.append(words[idx])
    out = separator.join(picks)
    if extra_digits_suffix > 0:
        digits = "".join(str(_safe_randint(0, 9, rng_secrets, rnd)) for _ in range(extra_digits_suffix))
        out = out + digits
    return out

class GeneratePassphrase:
    """
    Générateur de passphrase sécurisé.
    - random_chars : jeu de caractères configurable
    - diceware : mots aléatoires depuis un fichier wordlist (un mot par ligne)
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "mode": (["random_chars", "diceware"], {"default": "random_chars"}),
            },
            "optional": {
                # random_chars
                "length": ("INT", {"default": 20, "min": 4, "max": 256}),
                "use_lowercase": ("BOOLEAN", {"default": True}),
                "use_uppercase": ("BOOLEAN", {"default": True}),
                "use_digits": ("BOOLEAN", {"default": True}),
                "use_symbols": ("BOOLEAN", {"default": True}),
                "exclude_ambiguous": ("BOOLEAN", {"default": True}),
                # diceware
                "diceware_wordlist_path": ("STRING", {"default": "", "multiline": False}),
                "num_words": ("INT", {"default": 8, "min": 2, "max": 32}),
                "separator": ("STRING", {"default": "-", "multiline": False}),
                # commun
                "extra_digits_suffix": ("INT", {"default": 0, "min": 0, "max": 10}),
                "deterministic_seed": ("INT", {"default": -1, "min": -1, "max": 2**31-1}),
            }
        }

    RETURN_TYPES = ("STRING", "FLOAT", "STRING")
    RETURN_NAMES = ("passphrase", "entropy_bits", "recipe")
    FUNCTION = "run"
    CATEGORY = CATEGORY

    def run(
        self,
        mode="random_chars",
        length=20,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=True,
        diceware_wordlist_path="",
        num_words=8,
        separator="-",
        extra_digits_suffix=0,
        deterministic_seed=-1,
    ):
        # Sélection RNG
        rng_secrets = deterministic_seed < 0
        rnd = None
        if not rng_secrets:
            rnd = random.Random(deterministic_seed)

        if mode == "diceware":
            # Charge wordlist
            try:
                words = _load_wordlist(diceware_wordlist_path)
            except Exception as e:
                return (f"[GeneratePassphrase ERROR] {type(e).__name__}: {e}", 0.0, "load_wordlist_failed")

            passphrase = _gen_diceware(num_words, words, separator, extra_digits_suffix, rng_secrets, rnd)
            entropy = _entropy_diceware(num_words, len(words), extra_digits_suffix)
            recipe = f"mode=diceware; words={num_words}; vocab={len(words)}; sep={repr(separator)}; digits+={extra_digits_suffix}; rng={'secrets' if rng_secrets else 'deterministic'}"
            if not rng_secrets:
                recipe += " [WARNING: deterministic RNG — dev/test only]"
            return (passphrase, float(entropy), recipe)

        # random_chars
        charset = _build_charset(use_lowercase, use_uppercase, use_digits, use_symbols, exclude_ambiguous)
        passphrase = _gen_random_chars(length, charset, extra_digits_suffix, rng_secrets, rnd)
        entropy = _entropy_random_chars(length, len(charset), extra_digits_suffix)
        recipe = (
            f"mode=random_chars; length={length}; alphabet={len(charset)};"
            f" lower={use_lowercase}; upper={use_uppercase}; digits={use_digits}; symbols={use_symbols};"
            f" exclude_ambiguous={exclude_ambiguous}; digits+={extra_digits_suffix};"
            f" rng={'secrets' if rng_secrets else 'deterministic'}"
        )
        if not rng_secrets:
            recipe += " [WARNING: deterministic RNG — dev/test only]"
        return (passphrase, float(entropy), recipe)


NODE_CLASS_MAPPINGS = {
    "GeneratePassphrase": GeneratePassphrase,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "GeneratePassphrase": "Generate Passphrase",
}
