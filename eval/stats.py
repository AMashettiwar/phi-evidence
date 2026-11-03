"""The statistics the brief names (section 7): Wilson intervals, an exact
McNemar test, and a power analysis printed before the run.

Standard library only, so a reviewer can check every number by hand.
"""

from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a proportion. (0, 1) when n is 0."""
    if n == 0:
        return 0.0, 1.0
    p = successes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts b and c:
    b = items only the first arm got right, c = only the second."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def min_successes(n: int, point: float, lower: float) -> int | None:
    """Fewest successes out of n meeting both a point estimate and a Wilson
    lower bound. None means no outcome at this n can pass: undecidable."""
    for x in range(n + 1):
        if x / n >= point and wilson(x, n)[0] >= lower:
            return x
    return None


def pass_probability(n: int, true_rate: float, needed: int) -> float:
    """Chance of at least `needed` successes out of n if the true rate is
    true_rate: the power of the acceptance rule at that rate."""
    return sum(math.comb(n, x) * true_rate ** x * (1 - true_rate) ** (n - x)
               for x in range(needed, n + 1))


def mcnemar_n_needed(rate_b: float, rate_c: float, alpha: float = 0.05) -> int:
    """Smallest number of discordant pairs at which the expected split would
    reach significance; used to say what n would decide an undecided test."""
    if rate_c == rate_b:
        return 0
    share = max(rate_b, rate_c) / (rate_b + rate_c)
    for n in range(1, 10000):
        small = round(n * (1 - share))
        if mcnemar_exact(small, n - small) < alpha:
            return n
    return 10000
