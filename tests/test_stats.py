import pytest

from eval.stats import mcnemar_exact, min_successes, pass_probability, wilson


def test_wilson_matches_published_values():
    # Newcombe (1998), table I: 81/263 -> 0.2553 to 0.3662.
    low, high = wilson(81, 263)
    assert low == pytest.approx(0.2553, abs=1e-3) and high == pytest.approx(0.3662, abs=1e-3)
    assert wilson(0, 0) == (0.0, 1.0)


def test_mcnemar_exact():
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(0, 6) == pytest.approx(0.03125)
    assert mcnemar_exact(0, 5) == pytest.approx(0.0625)
    assert mcnemar_exact(3, 3) == 1.0


def test_acceptance_rule_at_160():
    needed = min_successes(160, 0.95, 0.90)
    assert needed == 152
    assert wilson(152, 160)[0] >= 0.90 > wilson(151, 160)[0] or 151 / 160 < 0.95
    assert min_successes(20, 0.95, 0.90) is None  # undecidable at small n
    assert pass_probability(160, 0.99, needed) > 0.99
