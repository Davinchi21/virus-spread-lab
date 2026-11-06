"""Экспорт данных для веб-симулятора и эталонов для проверки совпадения Python и JS."""
from __future__ import annotations

import glob
import json
import os

from . import network as netmod
from .experiments import normalize, run
from .simulation import DEFAULT_PARAMS, MODELS
from .viruses import VIRUS_PARAMS, VIRUSES

HEADER = "// Файл сгенерирован командой `python -m virus_lab build-web`. Не редактируйте вручную.\n"

PARITY_CASES = [
    {"name": "corporate / SIR / сетевой червь", "seed": 1},
    {"name": "corporate / SEIR / червь + реагирование", "seed": 11, "model": "SEIR",
     "params": {"detect_threshold": 0.05, "response_delay": 5, "response_patch_rate": 0.1,
                "response_segmentation": True, "response_quarantine": 0.2}},
    {"name": "small_world / SIS / почтовый червь", "seed": 7, "model": "SIS", "virus": "email_worm",
     "network": {"topology": "small_world"}, "params": {"max_steps": 150}},
    {"name": "scale_free / SI / USB-вирус", "seed": 3, "model": "SI", "virus": "usb_virus",
     "network": {"topology": "scale_free"}},
    {"name": "random / SIR / APT + сегментация", "seed": 5, "virus": "apt_stealth",
     "network": {"topology": "random"}, "params": {"segmentation": True, "initial_infected": 3}},
    {"name": "ring / SIR / Linux-червь", "seed": 9, "virus": "linux_worm", "network": {"topology": "ring"}},
    {"name": "grid / SEIR / сетевой червь", "seed": 13, "model": "SEIR", "network": {"topology": "grid"}},
    {"name": "star / SIR / сетевой червь", "seed": 17, "network": {"topology": "star", "patch_coverage": 0.2}},
    {"name": "flat / SIR / почтовый червь", "seed": 19, "virus": "email_worm", "network": {"topology": "flat"},
     "params": {"patient_zero": 25}},
    {"name": "corporate / SIR / торрент-троян + офлайн-ПК", "seed": 3, "virus": "torrent_trojan",
     "network": {"topology": "corporate", "p2p_share": 0.35, "offline_share": 0.15}, "params": {"max_steps": 300}},
    {"name": "corporate / SEIR / торрент-червь (2 канала)", "seed": 5, "model": "SEIR", "virus": "torrent_worm",
     "network": {"topology": "corporate", "p2p_share": 0.25, "offline_share": 0.1},
     "params": {"initial_infected": 0, "max_steps": 300}},
    {"name": "flat / SIR / торрент-троян + блокировка P2P", "seed": 8, "virus": "torrent_trojan",
     "network": {"topology": "flat", "hosts": 60, "subnets": 1, "p2p_share": 0.5, "offline_share": 0.2},
     "params": {"p2p_blocked": True, "max_steps": 250}},
    {"name": "corporate / SIR / 300 ПК, реагирование", "seed": 7, "virus": "worm_smb",
     "network": {"topology": "corporate", "hosts": 300, "subnets": 10, "cross_links": 40},
     "params": {"detect_threshold": 0.05, "response_delay": 8, "response_patch_rate": 0.1,
                "response_segmentation": True, "response_quarantine": 0.15}},
    {"name": "flat / SIR / малый офис, 20 ПК", "seed": 42, "virus": "worm_smb",
     "network": {"topology": "flat", "hosts": 20, "subnets": 1, "patch_coverage": 0.3}},
]


def _parity_case(spec: dict) -> dict:
    sc = normalize({k: v for k, v in spec.items() if k != "name"})
    sim = run(sc, keep_events=False)
    h = sim.history
    return {
        "name": spec["name"],
        "scenario": sc,
        "expected": {
            "degrees": [len(nb) for nb in sim.net.neighbors],
            "os": [x.os for x in sim.hosts],
            "patched0": [1 if x.patched else 0 for x in sim.hosts],
            "av": [1 if x.av else 0 for x in sim.hosts],
            "p2p": [1 if x.p2p else 0 for x in sim.hosts],
            "offline": [1 if x.offline else 0 for x in sim.hosts],
            "S": [r["S"] for r in h], "E": [r["E"] for r in h],
            "I": [r["I"] for r in h], "R": [r["R"] for r in h],
            "ever": [r["ever"] for r in h],
            "attempts": sim.attempts, "blocked": sim.blocked,
            "state": sim.state, "infected_by": sim.infected_by,
            "infected_via": sim.infected_via, "by_channel": sim.by_channel,
        },
    }


def build_web(root: str) -> list[str]:
    web = os.path.join(root, "web")
    scen_dir = os.path.join(root, "scenarios")
    scenarios = []
    for path in sorted(glob.glob(os.path.join(scen_dir, "*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["file"] = os.path.basename(path)
        scenarios.append(data)
    data = {
        "viruses": VIRUSES,
        "virusParams": VIRUS_PARAMS,
        "models": MODELS,
        "topologies": netmod.TOPOLOGIES,
        "osNames": netmod.OS_NAMES,
        "subnetProfiles": netmod.SUBNET_PROFILES,
        "serverSubnetProfile": netmod.SERVER_SUBNET_PROFILE,
        "serverRoles": netmod.SERVER_ROLES,
        "coreServers": netmod.CORE_SERVERS,
        "defaultNetwork": netmod.DEFAULT_NETWORK,
        "defaultParams": DEFAULT_PARAMS,
        "scenarios": scenarios,
    }
    out1 = os.path.join(web, "data.js")
    with open(out1, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER + "window.VIRUS_LAB_DATA = " + json.dumps(data, ensure_ascii=False, indent=1) + ";\n")
    cases = [_parity_case(c) for c in PARITY_CASES]
    out2 = os.path.join(web, "parity_fixture.js")
    with open(out2, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER + "window.PARITY_CASES = " + json.dumps(cases, ensure_ascii=False) + ";\n")
    return [out1, out2]
