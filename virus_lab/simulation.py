"""Агентная (поузловая) модель распространения вируса в сети.

Каждый ПК находится в одном из состояний:
  S — уязвим (не заражён), E — инкубация (заражён, но ещё не распространяет),
  I — заражён и атакует другие ПК, R — вылечен или изолирован.

Вирус распространяется по двум каналам:
  * ЛВС — заражённый ПК атакует соседей по локальной сети (рёбра графа);
  * торрент (P2P) — заражённый торрент-пользователь раздаёт файл другим торрент-
    пользователям в любой точке сети, включая ПК, не подключённые к ЛВС; кроме того,
    торрент-пользователь может скачать заражённый файл из интернета.

Один шаг моделирования (порядок важен, он совпадает с web/engine.js):
  1. если наступило время реагирования — включаются меры защиты;
  2. заражение по ЛВС: каждый узел в I делает `contacts` попыток заразить случайного соседа;
  3. заражение через торрент между ПК сети (`p2p_contacts` попыток);
  4. заражение из интернета (`external_rate`);
  5. (SEIR) узлы в E переходят в I с вероятностью sigma;
  6. узлы в I вылечиваются: администратор (gamma), антивирус (av_detect), карантин;
  7. во время реагирования администраторы ставят патчи на уязвимые ПК;
  8. проверяется, обнаружен ли инцидент (доля когда-либо заражённых >= detect_threshold).
"""
from __future__ import annotations

from .network import Network
from .rng import Rng

S, E, I, R = 0, 1, 2, 3
STATE_KEYS = ("S", "E", "I", "R")
STATE_NAMES = ("уязвим", "инкубация", "заражён", "вылечен/изолирован")

MODELS = {
    "SI": "SI — заражённый узел остаётся заражённым навсегда",
    "SIS": "SIS — вылеченный узел снова может заразиться",
    "SIR": "SIR — вылеченный узел приобретает иммунитет",
    "SEIR": "SEIR — SIR со скрытым (инкубационным) периодом",
}

DEFAULT_PARAMS = {
    "gamma": 0.02,  # вероятность за шаг, что администратор сам найдёт и вылечит заражённый ПК
    "user_awareness": 0.3,  # осведомлённость персонала: доля пользователей, не открывающих вложения
    "segmentation": False,  # межсегментный МСЭ включён с самого начала
    "p2p_blocked": False,  # торренты заблокированы на периметре (не действует на ПК вне ЛВС)
    "initial_infected": 1,
    "patient_zero": -1,  # номер нулевого пациента (-1 — случайный)
    "detect_threshold": 0.1,  # доля заражённых ПК, при которой инцидент замечают
    "response_delay": 10,  # шагов от обнаружения до начала реагирования
    "response_patch_rate": 0.0,  # вероятность за шаг установить патч на каждый ПК без патча
    "response_segmentation": False,  # включить межсегментный МСЭ при реагировании
    "response_p2p_block": False,  # заблокировать торренты на периметре при реагировании
    "response_quarantine": 0.0,  # вероятность за шаг изолировать заражённый ПК при реагировании
    "max_steps": 300,
}

SIM_SEED_SALT = 0x9E3779B9
VIA_TEXT = {"seed": "нулевой пациент", "lan": "по ЛВС", "p2p": "через торрент", "ext": "из интернета (торрент)"}


class Simulation:
    def __init__(self, network: Network, virus: dict, model: str = "SIR", params: dict | None = None,
                 seed: int = 42, keep_events: bool = True):
        if model not in MODELS:
            raise ValueError(f"Неизвестная модель: {model}. Доступны: {', '.join(MODELS)}")
        self.net = network
        self.hosts = network.hosts
        self.n = len(self.hosts)
        self.virus = virus
        self.model = model
        self.params = {**DEFAULT_PARAMS, **(params or {})}
        self.seed = seed
        self.rng = Rng(int(seed) ^ SIM_SEED_SALT)
        self.keep_events = keep_events

        n = self.n
        self.state = [S] * n
        self.patched = [h.patched for h in self.hosts]
        self.targeted = [h.os in virus["targets"] for h in self.hosts]
        self.p2p_users = [h.id for h in self.hosts if h.p2p]
        self.was_infected = [False] * n
        self.infected_by = [-1] * n
        self.infected_at = [-1] * n
        self.infected_via = [""] * n
        self.generation = [-1] * n
        self.offspring = [0] * n
        self.seeds: list[int] = []  # нулевые пациенты и заражённые из интернета
        self.first_episode = [False] * n  # такой ПК ещё ни разу не вылечен
        self.seed_offspring = 0  # сколько ПК они заразили за первый эпизод болезни
        self.by_channel = {"seed": 0, "lan": 0, "p2p": 0, "ext": 0}

        self.t = 0
        self.ever = 0  # число разных ПК, заражавшихся хотя бы раз
        self.infections = 0  # всего случаев заражения (в SIS один ПК может заразиться несколько раз)
        self.new_last = 0
        self.attempts = 0
        self.blocked = 0
        self.seg_active = bool(self.params["segmentation"])
        self.p2p_block = bool(self.params["p2p_blocked"])
        self.detected_at: int | None = None
        self.response_at: int | None = None
        self.response_active = False
        self.finished = False
        self.end_reason = ""
        self.events: list[tuple[int, str, str]] = []
        self.history: list[dict] = []

        self.vulnerable_at_start = sum(1 for i in range(n) if not self.is_protected(i))
        self._seed_infection()
        self.new_last = self.infections
        self._record()
        if self._active() == 0 and not self._influx_possible():
            self._finish("Заражённых узлов нет — эпидемия не началась")

    # ------------------------------------------------------------------ служебное
    def _log(self, kind: str, text: str) -> None:
        if self.keep_events:
            self.events.append((self.t, kind, text))

    def _name(self, i: int) -> str:
        h = self.hosts[i]
        return f"{h.hostname} ({h.ip})"

    def _active(self) -> int:
        return sum(1 for s in self.state if s == E or s == I)

    def _finish(self, reason: str) -> None:
        self.finished = True
        self.end_reason = reason
        self._log("end", reason)

    def _infect(self, j: int, src: int, new_state: int, via: str) -> None:
        self.state[j] = new_state
        self.infected_by[j] = src
        self.infected_at[j] = self.t
        self.infected_via[j] = via
        self.generation[j] = 0 if src < 0 else self.generation[src] + 1
        if src >= 0:
            self.offspring[src] += 1
            if self.first_episode[src]:
                self.seed_offspring += 1
        else:
            self.seeds.append(j)
            self.first_episode[j] = True
        if not self.was_infected[j]:
            self.was_infected[j] = True
            self.ever += 1
        self.infections += 1
        self.by_channel[via] += 1
        if via == "seed":
            self._log("infect", f"Нулевой пациент: {self._name(j)}")
        elif via == "ext":
            self._log("infect", f"{self._name(j)} скачал заражённый файл из торрента")
        else:
            self._log("infect", f"{self._name(src)} заразил {self._name(j)} {VIA_TEXT[via]}")

    def _seed_infection(self) -> None:
        eligible = [i for i in range(self.n) if self.targeted[i]]
        if not eligible:
            self._log("info", "Вирус не может заразить ни один узел: в сети нет подходящих ОС")
            return
        k = max(0, min(int(self.params["initial_infected"]), len(eligible)))
        count = 0
        pz = self.params["patient_zero"]
        if isinstance(pz, int) and 0 <= pz < self.n and k > 0:
            if self.targeted[pz]:
                self._infect(pz, -1, I, "seed")
                count = 1
            else:
                self._log("info", f"{self._name(pz)}: ОС не поражается этим вирусом, нулевой пациент выбран случайно")
        while count < k:
            j = eligible[self.rng.randint(len(eligible))]
            if self.state[j] == S:
                self._infect(j, -1, I, "seed")
                count += 1

    def _record(self) -> None:
        c = [0, 0, 0, 0]
        for s in self.state:
            c[s] += 1
        self.history.append({
            "t": self.t, "S": c[S], "E": c[E], "I": c[I], "R": c[R],
            "ever": self.ever, "new": self.new_last, "attempts": self.attempts,
            "blocked": self.blocked, "patched": sum(self.patched),
        })

    # ------------------------------------------------------------------ вероятности
    def lan_prob(self, j: int) -> float:
        """Вероятность заразить узел j одной попыткой по ЛВС (без учёта МСЭ)."""
        if not self.targeted[j]:
            return 0.0
        v = self.virus
        if v["needs_vuln"] and self.patched[j]:
            return 0.0
        p = v["beta"]
        if v["user_action"]:
            p *= 1.0 - self.params["user_awareness"]
        if self.hosts[j].av:
            p *= 1.0 - v["av_block"]
        return p

    infection_prob = lan_prob  # совместимость

    def p2p_prob(self, j: int) -> float:
        """Вероятность, что торрент-пользователь j запустит заражённый файл (патч не защищает)."""
        if not self.targeted[j] or not self.hosts[j].p2p:
            return 0.0
        p = self.virus["p2p_beta"] * (1.0 - self.params["user_awareness"])
        if self.hosts[j].av:
            p *= 1.0 - self.virus["av_block"]
        return p

    def p2p_open(self, j: int) -> bool:
        """Торрент-трафик ПК j не заблокирован (блокировка на периметре не касается ПК вне ЛВС)."""
        h = self.hosts[j]
        return h.p2p and not (self.p2p_block and not h.offline)

    def is_protected(self, j: int) -> bool:
        """Ни по ЛВС, ни через торрент этот ПК сейчас заразить нельзя."""
        v = self.virus
        lan = v["contacts"] > 0 and len(self.net.neighbors[j]) > 0 and self.lan_prob(j) > 0
        p2p = (v["p2p_contacts"] > 0 or v["external_rate"] > 0) and self.p2p_open(j) and self.p2p_prob(j) > 0
        return not (lan or p2p)

    def _influx_possible(self) -> bool:
        if self.virus["external_rate"] <= 0:
            return False
        return any(self.state[j] == S and self.p2p_open(j) and self.p2p_prob(j) > 0 for j in self.p2p_users)

    # ------------------------------------------------------------------ шаг
    def step(self) -> bool:
        """Один шаг моделирования. Возвращает False, если моделирование закончено."""
        if self.finished:
            return False
        self.t += 1
        p, v, rng, n = self.params, self.virus, self.rng, self.n

        if not self.response_active and self.response_at is not None and self.t >= self.response_at:
            self.response_active = True
            if p["response_segmentation"]:
                self.seg_active = True
            if p["response_p2p_block"]:
                self.p2p_block = True
            self._log("response", "Начато реагирование на инцидент")

        start = self.state[:]
        before = self.infections
        target_state = E if self.model == "SEIR" else I

        # 2. Заражение по ЛВС
        lan_contacts = int(v["contacts"])
        if lan_contacts > 0:
            for i in range(n):
                if start[i] != I:
                    continue
                nb = self.net.neighbors[i]
                if not nb:
                    continue
                cross = self.net.cross[i]
                for _ in range(lan_contacts):
                    idx = rng.randint(len(nb))
                    j = nb[idx]
                    self.attempts += 1
                    if self.state[j] != S:
                        continue
                    if cross[idx] and self.seg_active and not rng.chance(v["firewall_bypass"]):
                        self.blocked += 1
                        continue
                    prob = self.lan_prob(j)
                    if prob <= 0.0:
                        continue
                    if rng.chance(prob):
                        self._infect(j, i, target_state, "lan")

        # 3. Заражение через торрент между ПК сети
        p2p_contacts = int(v["p2p_contacts"])
        users = self.p2p_users
        if p2p_contacts > 0 and len(users) > 1:
            for i in range(n):
                if start[i] != I or not self.hosts[i].p2p:
                    continue
                if not self.p2p_open(i):
                    self.attempts += p2p_contacts
                    self.blocked += p2p_contacts
                    continue
                for _ in range(p2p_contacts):
                    j = users[rng.randint(len(users))]
                    self.attempts += 1
                    if j == i or self.state[j] != S:
                        continue
                    if not self.p2p_open(j):
                        self.blocked += 1
                        continue
                    prob = self.p2p_prob(j)
                    if prob <= 0.0:
                        continue
                    if rng.chance(prob):
                        self._infect(j, i, target_state, "p2p")

        # 4. Заражение из интернета
        ext = v["external_rate"]
        if ext > 0:
            for j in users:
                if self.state[j] != S or not self.p2p_open(j):
                    continue
                prob = self.p2p_prob(j)
                if prob <= 0.0:
                    continue
                if rng.chance(ext * prob):
                    self._infect(j, -1, target_state, "ext")

        # 5. Инкубация
        if self.model == "SEIR":
            for i in range(n):
                if start[i] == E and rng.chance(v["sigma"]):
                    self.state[i] = I

        # 6. Лечение
        if self.model != "SI":
            q = p["response_quarantine"] if self.response_active else 0.0
            back = S if self.model == "SIS" else R
            for i in range(n):
                if start[i] != I:
                    continue
                avd = v["av_detect"] if self.hosts[i].av else 0.0
                pr = 1.0 - (1.0 - p["gamma"]) * (1.0 - avd) * (1.0 - q)
                if rng.chance(pr):
                    self.state[i] = back
                    self.first_episode[i] = False
                    self._log("recover", f"{self._name(i)} вылечен/изолирован")

        # 7. Установка патчей
        if self.response_active and p["response_patch_rate"] > 0:
            for i in range(n):
                if not self.patched[i] and not self.hosts[i].legacy:
                    if rng.chance(p["response_patch_rate"]):
                        self.patched[i] = True

        # 8. Обнаружение инцидента
        if self.detected_at is None and self.ever >= p["detect_threshold"] * n:
            self.detected_at = self.t
            self.response_at = self.t + int(p["response_delay"])
            self._log("detect", f"Инцидент обнаружен: заражено {self.ever} ПК. "
                                f"Реагирование начнётся на шаге {self.response_at}")

        self.new_last = self.infections - before
        self._record()

        if self._active() == 0 and not self._influx_possible():
            self._finish("Эпидемия завершилась: заражённых узлов не осталось")
        elif self.model == "SI" and not any(self.state[i] == S and not self.is_protected(i) for i in range(n)):
            self._finish("Все доступные для заражения узлы заражены")
        elif self.t >= int(p["max_steps"]):
            self._finish("Достигнут предел числа шагов")
        return not self.finished

    def run(self) -> "Simulation":
        while self.step():
            pass
        return self

    # ------------------------------------------------------------------ итоги
    def summary(self) -> dict:
        hist = self.history
        infected = [h["E"] + h["I"] for h in hist]
        peak = max(infected)
        peak_t = hist[infected.index(peak)]["t"]
        half = next((h["t"] for h in hist if h["ever"] * 2 >= self.n), None)
        subnets = []
        for s, name in enumerate(self.net.subnet_names()):
            members = [h.id for h in self.hosts if h.subnet == s]
            subnets.append({
                "subnet": name,
                "hosts": len(members),
                "infected": sum(1 for i in members if self.was_infected[i]),
            })
        offline = [h.id for h in self.hosts if h.offline]
        last = hist[-1]
        return {
            "steps": self.t,
            "end_reason": self.end_reason,
            "extinct": self._active() == 0,
            "vulnerable_at_start": self.vulnerable_at_start,
            "peak_infected": peak,
            "peak_step": peak_t,
            "ever_infected": self.ever,
            "ever_fraction": self.ever / self.n,
            "infections": self.infections,
            "by_channel": dict(self.by_channel),
            "half_network_step": half,
            "r0_gen0": self.seed_offspring / len(self.seeds) if self.seeds else 0.0,
            "attempts": self.attempts,
            "blocked": self.blocked,
            "detected_at": self.detected_at,
            "response_at": self.response_at,
            "final": {k: last[k] for k in STATE_KEYS},
            "subnets": subnets,
            "offline": {"hosts": len(offline), "infected": sum(1 for i in offline if self.was_infected[i])},
            "p2p_users": len(self.p2p_users),
        }
