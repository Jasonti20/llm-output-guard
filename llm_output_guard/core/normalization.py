from __future__ import annotations
import unicodedata
from typing import List, Tuple

_ZERO_WIDTH = {
    "\u200B",  # ZERO WIDTH SPACE
    "\u200C",  # ZERO WIDTH NON-JOINER
    "\u200D",  # ZERO WIDTH JOINER
    "\u200E",  # LEFT-TO-RIGHT MARK
    "\u200F",  # RIGHT-TO-LEFT MARK
    "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u2060",  # WORD JOINER
}

def normalize_text(text: str) -> str:
    """
    Returns (normalized_text, map_norm_to_orig, map_orig_to_norm)

    - Per-char NFKC fold
    - Remove zero-width characters
    - Build index maps so detector spans on normalized text can be mapped back
      to the original string for precise redaction.
    """
    norm_chars: List[str] = []
    map_norm_to_orig: List[int] = []
    map_orig_to_norm: List[int] = [-1] * len(text)  # -1 means removed
    
    norm_idx = 0
    for orig_idx, char in enumerate(text):
        if char in _ZERO_WIDTH:
            continue
        folded = unicodedata.normalize("NFKC", char)
        for sub in folded:
            norm_chars.append(sub)
            map_norm_to_orig.append(orig_idx)
            if map_orig_to_norm[orig_idx] == -1:
                map_orig_to_norm[orig_idx] = norm_idx
            norm_idx += 1
    
    return "".join(norm_chars), map_norm_to_orig, map_orig_to_norm

def to_original_span(norm_start: int, norm_end: int, map_norm_to_orig: List[int]) -> Tuple[int, int]:
    """
    Convert a [norm_start, norm_end) span to original [start, end).
    """
    if norm_start >= norm_end:
        return (0, 0)
    orig_start = map_norm_to_orig[norm_start]
    orig_end_inclusive = map_norm_to_orig[norm_end - 1]
    return orig_start, orig_end_inclusive + 1

        