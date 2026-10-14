"""Calculate byte entropy and scan supplied ranges for high-entropy windows."""

from collections import Counter
from collections.abc import Iterable
import math

from .analysis_constants import ENTROPY_SCAN_BYTES, MAX_ENTROPY_REGIONS
from .analysis_models import EntropyRegion


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence, rounded to three decimals."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)


def scan_entropy_regions(
    ranges: Iterable[tuple[str, int, int, bool]],
    data: bytes,
    window: int,
    threshold: float,
    notes: list[str],
) -> list[EntropyRegion]:
    """Find adjacent high-entropy windows across ordered file ranges."""
    results = []
    budget = ENTROPY_SCAN_BYTES
    for source, start, size, executable in ranges:
        available = max(0, min(size, len(data) - start))
        amount = min(available, budget)
        if amount < available:
            notes.append("Local entropy scan truncated at byte budget")
        budget -= amount
        previous = None
        for offset in range(start, start + amount, window):
            content = data[offset : min(offset + window, start + amount)]
            if len(content) < 512:
                continue
            entropy = calculate_entropy(content)
            if entropy < threshold:
                previous = None
                continue
            if (
                previous is not None
                and int(previous.file_offset, 16) + previous.size == offset
            ):
                previous.size += len(content)
                previous.peak_entropy = max(previous.peak_entropy, entropy)
                continue
            if len(results) >= MAX_ENTROPY_REGIONS:
                notes.append("Local entropy scan stopped at region limit")
                return results
            previous = EntropyRegion(
                source, hex(offset), len(content), entropy, executable
            )
            results.append(previous)
    return results
