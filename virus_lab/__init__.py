"""Лаборатория по изучению распространения компьютерных вирусов в сети из 100 ПК.

Это математическая модель: пакет не содержит вредоносного кода и не выполняет
никаких реальных сетевых действий.
"""
from .experiments import load_scenario, make_simulation, monte_carlo, normalize, run, set_value, sweep
from .network import Network, build_network
from .simulation import MODELS, Simulation
from .viruses import VIRUSES, get_virus

__version__ = "1.0.0"
__all__ = [
    "MODELS", "Network", "Simulation", "VIRUSES", "build_network", "get_virus", "load_scenario",
    "make_simulation", "monte_carlo", "normalize", "run", "set_value", "sweep",
]
