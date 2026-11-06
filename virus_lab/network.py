"""Генерация виртуальной сети из 100 ПК (и сетей других топологий).

ВАЖНО: порядок обращений к генератору случайных чисел здесь в точности
повторяет web/engine.js. Меняя алгоритм, меняйте его в обоих местах и
перегенерируйте web/parity_fixture.js (python -m virus_lab build-web).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict

from .rng import Rng

OS_NAMES = {
    "win7": "Windows 7 (снята с поддержки, патчи не выходят)",
    "win10": "Windows 10",
    "win11": "Windows 11",
    "winsrv": "Windows Server",
    "linux": "Linux",
}

# Профили отделов: название, префикс имени ПК и распределение ОС.
SUBNET_PROFILES = [
    {"name": "Администрация", "prefix": "adm", "os": [["win11", 0.7], ["win10", 0.3]]},
    {"name": "Бухгалтерия", "prefix": "buh", "os": [["win10", 0.8], ["win7", 0.2]]},
    {"name": "Разработка", "prefix": "dev", "os": [["linux", 0.5], ["win11", 0.3], ["win10", 0.2]]},
    {"name": "Производство", "prefix": "prod", "os": [["win7", 0.6], ["win10", 0.4]]},
]
# Последняя подсеть всегда серверная.
SERVER_SUBNET_PROFILE = {"name": "ИТ и серверы", "prefix": "it", "os": [["win11", 0.5], ["linux", 0.5]]}

SERVER_ROLES = [
    {"role": "dc", "name": "Контроллер домена", "os": "winsrv"},
    {"role": "fs", "name": "Файловый сервер", "os": "winsrv"},
    {"role": "mail", "name": "Почтовый сервер", "os": "linux"},
    {"role": "web", "name": "Веб-сервер", "os": "linux"},
    {"role": "db", "name": "Сервер БД", "os": "linux"},
]
# С первыми CORE_SERVERS серверами (DC, файловый, почтовый) связаны все рабочие станции.
CORE_SERVERS = 3

TOPOLOGIES = {
    "corporate": "Корпоративная сеть: отделы-подсети, общие серверы, межотдельные связи",
    "flat": "Плоская сеть: все ПК в одном сегменте (полный граф)",
    "star": "Звезда: все ПК связаны только с центральным сервером",
    "ring": "Кольцевая решётка",
    "grid": "Решётка (квадратная)",
    "random": "Случайный граф Эрдёша–Реньи",
    "small_world": "«Малый мир» Уоттса–Строгаца",
    "scale_free": "Безмасштабная сеть Барабаши–Альберт",
}

DEFAULT_NETWORK = {
    "topology": "corporate",
    "hosts": 100,
    "subnets": 5,
    "patch_coverage": 0.5,  # доля ПК с установленным патчем (кроме устаревших Windows 7)
    "av_coverage": 0.6,  # доля ПК с актуальным антивирусом
    "cross_links": 15,  # случайные межотдельные связи (corporate)
    "avg_degree": 6,  # средняя степень (random, ring, small_world)
    "rewire_p": 0.1,  # вероятность перезамыкания ребра (small_world)
    "ba_m": 3,  # число связей нового узла (scale_free)
    "p2p_share": 0.15,  # доля рабочих станций с торрент-клиентом
    "offline_share": 0.0,  # доля рабочих станций, НЕ подключённых к ЛВС (домашние, автономные)
}

MAX_HOSTS = 1000
MAX_PER_SUBNET = 240  # адреса .11–.250 в подсети /24


@dataclass
class Host:
    id: int
    hostname: str
    ip: str
    subnet: int
    subnet_name: str
    os: str
    role: str  # "workstation" | "server"
    role_name: str
    legacy: bool  # устаревшая ОС, патч установить нельзя
    patched: bool
    av: bool
    p2p: bool  # пользуется торрентами
    offline: bool  # не подключён к локальной сети

    def to_dict(self) -> dict:
        return asdict(self)


class Network:
    def __init__(self, hosts: list[Host], neighbors: list[list[int]], config: dict):
        self.hosts = hosts
        self.neighbors = neighbors
        self.cross = [[hosts[i].subnet != hosts[j].subnet for j in nb] for i, nb in enumerate(neighbors)]
        self.config = config
        self.topology = config["topology"]

    @property
    def size(self) -> int:
        return len(self.hosts)

    def edge_count(self) -> int:
        return sum(len(nb) for nb in self.neighbors) // 2

    def degree(self, i: int) -> int:
        return len(self.neighbors[i])

    def subnet_names(self) -> list[str]:
        names: dict[int, str] = {}
        for h in self.hosts:
            names.setdefault(h.subnet, h.subnet_name)
        return [names[k] for k in sorted(names)]

    def find(self, key) -> int:
        """Поиск узла по номеру, имени или IP-адресу."""
        if isinstance(key, int):
            if 0 <= key < self.size:
                return key
            raise KeyError(f"Нет узла с номером {key}")
        text = str(key).strip()
        if text.lstrip("-").isdigit():
            return self.find(int(text))
        for h in self.hosts:
            if text in (h.hostname, h.ip):
                return h.id
        raise KeyError(f"Узел не найден: {text}")


def _subnet_profile(s: int, k_sub: int) -> tuple[dict, str, str]:
    """Профиль подсети, её название и префикс имён."""
    if s == k_sub - 1:
        p = SERVER_SUBNET_PROFILE
        return p, p["name"], p["prefix"]
    p = SUBNET_PROFILES[s % len(SUBNET_PROFILES)]
    rnd = s // len(SUBNET_PROFILES)
    if rnd == 0:
        return p, p["name"], p["prefix"]
    return p, f'{p["name"]} {rnd + 1}', f'{p["prefix"]}{rnd + 1}'


def _pick_os(profile: dict, r: float) -> str:
    acc = 0.0
    for name, weight in profile["os"]:
        acc += weight
        if r < acc:
            return name
    return profile["os"][-1][0]


def build_network(config: dict | None, seed: int) -> Network:
    cfg = {**DEFAULT_NETWORK, **(config or {})}
    topo = cfg["topology"]
    if topo not in TOPOLOGIES:
        raise ValueError(f"Неизвестная топология: {topo}. Доступны: {', '.join(TOPOLOGIES)}")
    n = int(cfg["hosts"])
    k_sub = int(cfg["subnets"])
    if n < 4 or n > MAX_HOSTS:
        raise ValueError(f"Число ПК должно быть от 4 до {MAX_HOSTS}")
    if k_sub < 1 or k_sub * 2 > n:
        raise ValueError("Число подсетей должно быть от 1 до половины числа ПК")
    if math.ceil(n / k_sub) > MAX_PER_SUBNET:
        raise ValueError(f"В подсети /24 помещается не более {MAX_PER_SUBNET} ПК — увеличьте число подсетей")
    rng = Rng(seed)

    # --- узлы ---
    hosts: list[Host] = []
    counters = [0] * k_sub
    for i in range(n):
        s = (i * k_sub) // n
        idx = counters[s]
        counters[s] += 1
        profile, sname, prefix = _subnet_profile(s, k_sub)
        r_os, r_patch, r_av = rng.random(), rng.random(), rng.random()
        r_p2p, r_off = rng.random(), rng.random()
        if s == k_sub - 1 and idx < len(SERVER_ROLES):
            srv = SERVER_ROLES[idx]
            os_name, role, role_name, hostname = srv["os"], "server", srv["name"], f'srv-{srv["role"]}'
        else:
            os_name, role, role_name = _pick_os(profile, r_os), "workstation", "Рабочая станция"
            hostname = f"{prefix}-pc{idx + 1:02d}"
        legacy = os_name == "win7"
        hosts.append(Host(
            id=i, hostname=hostname, ip=f"10.0.{s + 1}.{idx + 11}", subnet=s, subnet_name=sname,
            os=os_name, role=role, role_name=role_name, legacy=legacy,
            patched=(not legacy) and r_patch < cfg["patch_coverage"],
            av=r_av < cfg["av_coverage"],
            p2p=role == "workstation" and r_p2p < cfg["p2p_share"],
            offline=role == "workstation" and r_off < cfg["offline_share"],
        ))

    # --- связи ---
    adj: list[set[int]] = [set() for _ in range(n)]

    def link(a: int, b: int) -> None:
        if a != b:
            adj[a].add(b)
            adj[b].add(a)

    def ring_lattice(k: int) -> None:
        for i in range(n):
            for d in range(1, k + 1):
                link(i, (i + d) % n)

    server_start = next(h.id for h in hosts if h.subnet == k_sub - 1)

    if topo == "corporate":
        for s in range(k_sub):
            members = [h.id for h in hosts if h.subnet == s]
            for a_i, a in enumerate(members):
                for b in members[a_i + 1:]:
                    link(a, b)
        core = [h.id for h in hosts if h.role == "server"][:CORE_SERVERS]
        for h in hosts:
            if h.subnet != k_sub - 1:
                for c in core:
                    link(h.id, c)
        for _ in range(int(cfg["cross_links"])):
            a, b = rng.randint(n), rng.randint(n)
            if hosts[a].subnet != hosts[b].subnet:
                link(a, b)
    elif topo == "flat":
        for a in range(n):
            for b in range(a + 1, n):
                link(a, b)
    elif topo == "star":
        for i in range(n):
            link(server_start, i)
    elif topo == "ring":
        ring_lattice(max(1, int(cfg["avg_degree"]) // 2))
    elif topo == "grid":
        side = math.ceil(math.sqrt(n))
        for i in range(n):
            if (i % side) + 1 < side and i + 1 < n:
                link(i, i + 1)
            if i + side < n:
                link(i, i + side)
    elif topo == "random":
        p = float(cfg["avg_degree"]) / (n - 1)
        for a in range(n):
            for b in range(a + 1, n):
                if rng.chance(p):
                    link(a, b)
    elif topo == "small_world":
        k = max(1, int(cfg["avg_degree"]) // 2)
        ring_lattice(k)
        for i in range(n):
            for d in range(1, k + 1):
                j = (i + d) % n
                if rng.chance(cfg["rewire_p"]):
                    c = rng.randint(n)
                    if c != i and c not in adj[i] and j in adj[i]:
                        adj[i].discard(j)
                        adj[j].discard(i)
                        link(i, c)
    elif topo == "scale_free":
        m = max(1, min(int(cfg["ba_m"]), n - 1))
        repeated: list[int] = []
        for a in range(m + 1):
            for b in range(a + 1, m + 1):
                link(a, b)
                repeated.append(a)
                repeated.append(b)
        for v in range(m + 1, n):
            targets: list[int] = []
            while len(targets) < m:
                t = repeated[rng.randint(len(repeated))]
                if t not in targets:
                    targets.append(t)
            for t in sorted(targets):
                link(v, t)
                repeated.append(t)
                repeated.append(v)

    # Автономные ПК не подключены к ЛВС: у них нет сетевых связей.
    for h in hosts:
        if h.offline:
            for j in adj[h.id]:
                adj[j].discard(h.id)
            adj[h.id].clear()

    neighbors = [sorted(a) for a in adj]
    return Network(hosts, neighbors, cfg)
