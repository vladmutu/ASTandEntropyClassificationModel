import numpy as np


def calculate_shannon_entropy(file_bytes: bytes) -> float:
    """Compute Shannon entropy in bits/byte for a byte sequence.

    Returns a value in [0, 8]. Empty input returns 0.0.
    """
    if not file_bytes:
        return 0.0

    values = np.frombuffer(file_bytes, dtype=np.uint8)
    counts = np.bincount(values, minlength=256)
    probabilities = counts[counts > 0] / values.size
    entropy = float(-np.sum(probabilities * np.log2(probabilities)))

    if entropy < 0.0:
        return 0.0
    if entropy > 8.0:
        return 8.0
    return entropy
