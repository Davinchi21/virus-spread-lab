"""Сценарии, серии прогонов (метод Монте-Карло) и перебор параметров."""
from __future__ import annotations

import copy
import json
import math
import statistics

from .network import DEFAULT_NETWORK, build_network
from .simulation import DEFAULT_PARAMS, MODELS, STATE_KEYS, Simulation
from .viruses import get_virus

DEFAULT_SCENARIO = {
    "name": "Сценарий по умолчанию",
    "description": "",
    "seed": 42,
    "network_seed": None,  # None — сеть строится с тем же seed, что и эпидемия
    "model": "SIR",
    "virus": "worm_smb",
    "network": {},
    "params": {},
}


def normalize(scenario: dict | None) -> dict:
    """Дополняет сценарий значениями по умолчанию."""
    out = copy.deepcopy(DEFAULT_SCENARIO)
    for key, value in (scenario or {}).items():
        out[key] = copy.deepcopy(value)
    out["network"] = {**DEFAULT_NETWORK, **(out.get("network") or {})}
    out["params"] = {**DEFAULT_PARAMS, **(out.get("params") or {})}
    out["virus"] = get_virus(out["virus"])
    if out["model"] not in MODELS:
        raise ValueError(f"Неизвестная модель: {out['model']}")
    return out


def load_scenario(path: str | None) -> dict:
    if not path:
        return normalize(None)
    with open(path, encoding="utf-8") as f:
        return normalize(json.load(f))


def parse_value(raw: str):
    text = raw.strip()
    low = text.lower()
    if low in ("true", "да", "on"):
        return True
    if low in ("false", "нет", "off"):
        return False
    if low in ("null", "none"):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def set_value(scenario: dict, path: str, value) -> None:
    """Изменяет параметр сценария по пути вида "network.patch_coverage"."""
    if isinstance(value, str):
        value = parse_value(value)
    parts = path.split(".")
    if parts == ["virus"]:
        scenario["virus"] = get_virus(value)
        return
    if len(parts) == 1:
        if parts[0] not in DEFAULT_SCENARIO:
            raise KeyError(f"Неизвестный параметр: {path}")
        scenario[parts[0]] = value
        return
    if len(parts) != 2 or parts[0] not in ("network", "params", "virus"):
        raise KeyError(f"Неизвестный параметр: {path}")
    section = scenario[parts[0]]
    if parts[1] not in section:
        raise KeyError(f"Неизвестный параметр: {path}. Доступны: {', '.join(sorted(section))}")
    section[parts[1]] = value


def make_simulation(scenario: dict, seed: int | None = None, keep_events: bool = True) -> Simulation:
    seed = scenario["seed"] if seed is None else seed
    net_seed = scenario.get("network_seed")
    net = build_network(scenario["network"], seed if net_seed is None else net_seed)
    params = dict(scenario["params"])
    pz = params.get("patient_zero", -1)
    if isinstance(pz, str):
        params["patient_zero"] = net.find(pz)
    return Simulation(net, scenario["virus"], scenario["model"], params, seed, keep_events)


def run(scenario: dict, seed: int | None = None, keep_events: bool = True) -> Simulation:
    return make_simulation(scenario, seed, keep_events).run()


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else math.nan


def _std(xs: list[float]) -> float:
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


def mean_curves(sims: list[Simulation]) -> list[dict]:
    """Средние по прогонам кривые S, E, I, R, ever (короткие прогоны продлеваются последним значением)."""
    length = max(len(s.history) for s in sims)
    out = []
    for t in range(length):
        row = {"t": t}
        for key in STATE_KEYS + ("ever",):
            row[key] = _mean([s.history[min(t, len(s.history) - 1)][key] for s in sims])
        out.append(row)
    return out


def monte_carlo(scenario: dict, runs: int, base_seed: int | None = None) -> list[Simulation]:
    base = scenario["seed"] if base_seed is None else base_seed
    return [run(scenario, base + k, keep_events=False) for k in range(runs)]


def aggregate(sims: list[Simulation], outbreak_level: float = 0.2) -> dict:
    sums = [s.summary() for s in sims]
    ever = [x["ever_fraction"] for x in sums]
    peak = [x["peak_infected"] for x in sums]
    peak_t = [x["peak_step"] for x in sums]
    steps = [x["steps"] for x in sums]
    r0 = [x["r0_gen0"] for x in sums]
    blocked = [x["blocked"] for x in sums]
    return {
        "runs": len(sims),
        "ever_mean": _mean(ever),
        "ever_std": _std(ever),
        "peak_mean": _mean(peak),
        "peak_std": _std(peak),
        "peak_step_mean": _mean(peak_t),
        "steps_mean": _mean(steps),
        "r0_mean": _mean(r0),
        "blocked_mean": _mean(blocked),
        "outbreak_prob": sum(1 for e in ever if e >= outbreak_level) / len(ever),
    }


def sweep(scenario: dict, path: str, values: list, runs: int, base_seed: int | None = None) -> list[dict]:
    rows = []
    for value in values:
        sc = copy.deepcopy(scenario)
        set_value(sc, path, value)
        sims = monte_carlo(sc, runs, base_seed)
        rows.append({"value": value, **aggregate(sims), "curve": mean_curves(sims)})
    return rows
