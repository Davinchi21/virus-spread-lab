"""Аналитическая (среднеполевая) модель для сравнения с агентной.

Предположение «полного перемешивания»: каждый заражённый ПК атакует случайные
ПК всей сети (сеть — полный граф), все уязвимые ПК одинаковы. Структура сети,
сегментация и реагирование НЕ учитываются — в этом и смысл сравнения.

Дискретная схема (аналог цепной биномиальной модели Рида–Фроста):
  lambda_t = 1 - (1 - p/(N-1))^(c * I_t)    — вероятность для уязвимого ПК заразиться за шаг
  новые заражения = S_t * lambda_t
  выздоровления   = g * I_t
Базовое репродуктивное число: R0 = c * p * Nv/(N-1) / g.
"""
from __future__ import annotations

import math

from .network import Network
from .simulation import DEFAULT_PARAMS


def _infection_prob(host, virus: dict, params: dict, patched: bool) -> float:
    if host.os not in virus["targets"]:
        return 0.0
    if virus["needs_vuln"] and patched:
        return 0.0
    p = virus["beta"]
    if virus["user_action"]:
        p *= 1.0 - params["user_awareness"]
    if host.av:
        p *= 1.0 - virus["av_block"]
    return p


def parameters(network: Network, virus: dict, model: str, params: dict | None = None) -> dict:
    """Эффективные параметры однородной модели и пороговые величины."""
    p = {**DEFAULT_PARAMS, **(params or {})}
    hosts = network.hosts
    n = len(hosts)
    probs = [_infection_prob(h, virus, p, h.patched) for h in hosts]
    elig = [q for q in probs if q > 0]
    nv = len(elig)
    p_avg = sum(elig) / nv if nv else 0.0
    targeted = [h for h in hosts if h.os in virus["targets"]]
    if model == "SI" or not targeted:
        g = 0.0
    else:
        g = sum(1.0 - (1.0 - p["gamma"]) * (1.0 - (virus["av_detect"] if h.av else 0.0)) for h in targeted) / len(targeted)
    c = int(virus["contacts"])
    # Торрент-канал: заражённый торрент-пользователь раздаёт файл c_p2p другим из Up торрент-ПК.
    users = [h for h in hosts if h.p2p and h.os in virus["targets"]]
    up = len(users)
    cp = int(virus.get("p2p_contacts", 0))
    pp = virus.get("p2p_beta", 0.0) * (1.0 - p["user_awareness"])
    pp_list = [pp * (1.0 - virus["av_block"]) if h.av else pp for h in users]
    pp_avg = sum(pp_list) / up if up else 0.0
    beta_lan = c * p_avg * nv / (n - 1) if n > 1 else 0.0
    beta_p2p = cp * pp_avg * (up - 1) / (n - 1) if n > 1 else 0.0
    beta_eff = beta_lan + beta_p2p
    r0 = beta_eff / g if g > 0 else math.inf

    # Сколько ПК вообще можно заразить хотя бы по одному каналу
    lan_set = {h.id for h, q in zip(hosts, probs) if q > 0} if c > 0 else set()
    p2p_set = {h.id for h in users} if (cp > 0 or virus.get("external_rate", 0) > 0) and pp_avg > 0 else set()
    susceptible_total = len(lan_set | p2p_set)
    lan_dominant = beta_lan >= beta_p2p
    main_channel = "торрент (P2P)" if beta_p2p > beta_lan else "локальная сеть (ЛВС)"

    # R0 при полном отсутствии патчей (все заражаемые ПК уязвимы) — для оценки коллективного иммунитета.
    # Патч защищает только от канала needs_vuln; против торрент-трояна (needs_vuln=False) он бесполезен.
    if virus["needs_vuln"]:
        probs0 = [_infection_prob(h, virus, p, False) for h in hosts]
        elig0 = [q for q in probs0 if q > 0]
        beta0 = c * (sum(elig0) / len(elig0) if elig0 else 0.0) * len(elig0) / (n - 1) if n > 1 else 0.0
        beta0 += beta_p2p
        r0_nopatch = beta0 / g if g > 0 else math.inf
        patch_helps = True
    else:
        r0_nopatch = r0  # патч ничего не меняет
        patch_helps = False
    if math.isinf(r0_nopatch):
        herd = 1.0
    elif r0_nopatch <= 1.0 or not patch_helps:
        herd = 0.0
    else:
        herd = 1.0 - 1.0 / r0_nopatch  # доля заражаемых ПК, которую нужно защитить (1 - 1/R0)
    return {
        "N": n,
        "vulnerable": nv,
        "susceptible_total": susceptible_total,
        "p_avg": p_avg,
        "contacts": c,
        "gamma_eff": g,
        "beta_eff": beta_eff,
        "R0": r0,
        "R0_no_patch": r0_nopatch,
        "herd_immunity": herd,
        "patch_helps": patch_helps,
        "targeted": len(targeted),
        "beta_lan": beta_lan,
        "beta_p2p": beta_p2p,
        "p2p_users": up,
        "main_channel": main_channel,
    }


def final_size_sir(r0: float) -> float:
    """Доля переболевших среди уязвимых по уравнению Кермака–Маккендрика z = 1 - exp(-R0*z)."""
    if r0 <= 1:
        return 0.0
    if math.isinf(r0):
        return 1.0
    z = 0.5
    for _ in range(200):
        z = 1.0 - math.exp(-r0 * z)
    return z


def mean_field(network: Network, virus: dict, model: str, params: dict | None = None,
               steps: int | None = None) -> list[dict]:
    """Кривые S, E, I, R однородной модели (ожидаемые значения, дробные числа ПК)."""
    p = {**DEFAULT_PARAMS, **(params or {})}
    th = parameters(network, virus, model, p)
    n, nv, p_avg, c, g = th["N"], th["vulnerable"], th["p_avg"], th["contacts"], th["gamma_eff"]
    # Число заражаемых ПК с учётом торрент-канала: LAN-уязвимые плюс торрент-пользователи.
    nv_total = max(nv, 1) if (c > 0) else 0
    up = th["p2p_users"]
    cp = int(virus.get("p2p_contacts", 0))
    pp_avg = (th["beta_p2p"] * (n - 1) / (up - 1)) if (up > 1 and cp > 0) else 0.0
    susceptible0 = max(nv, up)  # грубая оценка: сколько ПК вообще можно заразить
    steps = int(p["max_steps"]) if steps is None else steps
    i0 = float(min(int(p["initial_infected"]), max(susceptible0, 1)))
    s_val = max(susceptible0 - i0, 0.0)
    e_val, i_val, r_val = 0.0, i0, 0.0
    immune = n - s_val - i_val  # неуязвимые ПК остаются в S навсегда
    ever = i0
    sigma = virus["sigma"]
    out = [{"t": 0, "S": s_val + immune, "E": e_val, "I": i_val, "R": r_val, "ever": ever}]
    for t in range(1, steps + 1):
        avoid_lan = (1.0 - p_avg / (n - 1)) ** (c * i_val) if n > 1 and c > 0 else 1.0
        avoid_p2p = (1.0 - pp_avg * up / n / (n - 1)) ** (cp * i_val) if n > 1 and cp > 0 else 1.0
        lam = 1.0 - avoid_lan * avoid_p2p
        new = s_val * lam
        rec = 0.0 if model == "SI" else g * i_val
        to_i = sigma * e_val if model == "SEIR" else 0.0
        s_val -= new
        if model == "SIS":
            s_val += rec
        else:
            r_val += rec
        if model == "SEIR":
            e_val += new - to_i
            i_val += to_i - rec
        else:
            i_val += new - rec
        ever += new if model != "SIS" else 0.0
        out.append({"t": t, "S": s_val + immune, "E": e_val, "I": i_val, "R": r_val,
                    "ever": min(ever, float(n))})
        if e_val + i_val < 0.01:
            break
    return out
