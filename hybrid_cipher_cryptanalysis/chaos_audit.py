"""Stage 3 / RQ5: Brent cycle detection on the digital logistic map."""
from construction_b import LOCKED_MU, LOCKED_X0, LOCKED_EPSILON


def _step(x, mu, eps, n):
    return (mu * x * (1 - x) + eps * n) % 1.0


def brent_cycle_detect(mu, x0, eps, max_iterations):
    """Returns (cycle_length or None, iterations_used)."""
    n = 0

    def f(x):
        nonlocal n
        n += 1
        return _step(x, mu, eps, n)

    power = lam = 1
    tortoise, hare = x0, f(x0)
    while tortoise != hare:
        if power == lam:
            tortoise, power, lam = hare, power * 2, 0
        hare = f(hare)
        lam += 1
        if n >= max_iterations:
            return None, n
    return lam, n


def run_audit(max_iterations):
    cases = [
        ("locked params (mu=3.99, perturbed)", LOCKED_MU, LOCKED_X0, LOCKED_EPSILON),
        ("unperturbed (epsilon=0)", LOCKED_MU, LOCKED_X0, 0.0),
        ("alternate x0", LOCKED_MU, 0.123456789, LOCKED_EPSILON),
        ("weaker chaos (mu=3.7, perturbed)", 3.7, LOCKED_X0, LOCKED_EPSILON),
    ]
    out = []
    for label, mu, x0, eps in cases:
        lam, used = brent_cycle_detect(mu, x0, eps, max_iterations)
        out.append({"case": label, "mu": mu, "x0": x0, "epsilon": eps,
                    "cycle_length": lam, "iterations_used": used,
                    "cycle_detected": lam is not None})
    return out
