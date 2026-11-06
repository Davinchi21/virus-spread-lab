"""Детерминированный генератор псевдослучайных чисел mulberry32.

Тот же алгоритм реализован в web/engine.js, поэтому при одинаковом seed
Python-версия и веб-симулятор дают побитово одинаковые результаты.
"""

MASK = 0xFFFFFFFF


def _imul(a: int, b: int) -> int:
    """Аналог Math.imul из JavaScript: младшие 32 бита произведения."""
    return (a * b) & MASK


class Rng:
    def __init__(self, seed: int):
        self.state = int(seed) & MASK

    def random(self) -> float:
        """Равномерное число в [0, 1)."""
        self.state = (self.state + 0x6D2B79F5) & MASK
        a = self.state
        t = _imul(a ^ (a >> 15), 1 | a)
        t = ((t + _imul(t ^ (t >> 7), 61 | t)) & MASK) ^ t
        return (t ^ (t >> 14)) / 4294967296.0

    def randint(self, n: int) -> int:
        """Целое число в [0, n)."""
        return int(self.random() * n)

    def chance(self, p: float) -> bool:
        """Событие с вероятностью p."""
        return self.random() < p
