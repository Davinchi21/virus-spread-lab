"""Командная строка лаборатории: python -m virus_lab <команда> ..."""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys

from . import theory
from .experiments import (aggregate, load_scenario, make_simulation, mean_curves, monte_carlo, set_value,
                          sweep)
from .network import OS_NAMES, TOPOLOGIES, build_network
from .plots import ascii_chart, plot_run, plot_sweep
from .simulation import MODELS
from .viruses import VIRUS_PARAMS, VIRUSES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pct(x: float) -> str:
    return f"{x * 100:.1f} %"


def _fmt(x) -> str:
    if x is None:
        return "—"
    if isinstance(x, float):
        return "∞" if math.isinf(x) else f"{x:.2f}"
    return str(x)


def _scenario(args) -> dict:
    sc = load_scenario(args.scenario)
    for attr, path in (("model", "model"), ("virus", "virus"), ("topology", "network.topology"), ("seed", "seed")):
        val = getattr(args, attr, None)
        if val is not None:
            set_value(sc, path, val)
    for item in args.set or []:
        if "=" not in item:
            raise SystemExit(f"--set ожидает ключ=значение, получено: {item}")
        key, value = item.split("=", 1)
        set_value(sc, key.strip(), value)
    return sc


def _write_csv(path: str, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=";")
        w.writeheader()
        w.writerows(rows)
    print(f"CSV сохранён: {path}")


# ---------------------------------------------------------------- команды
def cmd_inventory(args) -> None:
    sc = _scenario(args)
    seed = sc["seed"] if sc.get("network_seed") is None else sc["network_seed"]
    net = build_network(sc["network"], seed)
    print(f"Топология: {net.topology} — {TOPOLOGIES[net.topology]}")
    print(f"Узлов: {net.size}, связей: {net.edge_count()}, seed сети: {seed}\n")
    rows = []
    for h in net.hosts:
        rows.append({
            "№": h.id, "имя": h.hostname, "IP": h.ip, "подсеть": h.subnet_name, "роль": h.role_name,
            "ОС": h.os, "патч": "да" if h.patched else ("невозможен" if h.legacy else "нет"),
            "антивирус": "да" if h.av else "нет", "торрент": "да" if h.p2p else "нет",
            "вне ЛВС": "да" if h.offline else "нет", "связей": net.degree(h.id),
        })
    if args.csv:
        _write_csv(args.csv, rows)
    if not args.quiet:
        print(f"{'№':>3}  {'имя':<11} {'IP':<12} {'подсеть':<14} {'ОС':<7} {'патч':<10} {'АВ':<4} "
              f"{'торр':<5} {'вне ЛВС':<8} {'связей':>6}")
        for r in rows:
            print(f"{r['№']:>3}  {r['имя']:<11} {r['IP']:<12} {r['подсеть']:<14} {r['ОС']:<7} {r['патч']:<10} "
                  f"{r['антивирус']:<4} {r['торрент']:<5} {r['вне ЛВС']:<8} {r['связей']:>6}")
    print("\nСводка по подсетям:")
    for s, name in enumerate(net.subnet_names()):
        members = [h for h in net.hosts if h.subnet == s]
        os_count: dict[str, int] = {}
        for h in members:
            os_count[h.os] = os_count.get(h.os, 0) + 1
        print(f"  {name:<14} ПК: {len(members):>3}  с патчем: {sum(h.patched for h in members):>3}  "
              f"с АВ: {sum(h.av for h in members):>3}  ОС: " + ", ".join(f"{k}×{v}" for k, v in sorted(os_count.items())))
    print("\nОбозначения ОС: " + "; ".join(f"{k} — {v}" for k, v in OS_NAMES.items()))


def cmd_viruses(args) -> None:
    for vid, v in VIRUSES.items():
        print(f"{vid}: {v['name']}")
        print(f"    вектор: {v['vector']}")
        print(f"    аналоги: {v['analogs']}")
        print(f"    поражает: {', '.join(v['targets'])}; нужна уязвимость: {'да' if v['needs_vuln'] else 'нет'}; "
              f"нужен пользователь: {'да' if v['user_action'] else 'нет'}")
        print("    ЛВС:     " + ", ".join(f"{k}={v[k]}" for k in ("beta", "contacts", "av_block", "av_detect",
                                                              "firewall_bypass", "sigma")))
        if v.get("p2p_contacts") or v.get("external_rate"):
            print("    торрент: " + ", ".join(f"{k}={v[k]}" for k in ("p2p_beta", "p2p_contacts", "external_rate")))
        print()
    print("Параметры:")
    for k, d in VIRUS_PARAMS.items():
        print(f"  {k:<16} {d}")
    print("\nМодели:")
    for k, d in MODELS.items():
        print(f"  {d}")


def cmd_run(args) -> None:
    sc = _scenario(args)
    sim = make_simulation(sc)
    sim.run()
    s = sim.summary()
    net, v = sim.net, sim.virus
    print(f"Сценарий: {sc['name']}")
    print(f"Сеть: {net.topology}, {net.size} ПК, {net.edge_count()} связей | Вирус: {v['name']} | "
          f"Модель: {sim.model} | seed {sim.seed}")
    zero = [sim._name(i) for i in sim.seeds]
    print(f"Нулевой пациент: {', '.join(zero) or 'нет'}\n")
    print(ascii_chart(sim.history, sim.n))
    print("\nИтоги:")
    print(f"  Причина остановки ........... {s['end_reason']}")
    print(f"  Длительность ................ {s['steps']} шагов")
    print(f"  Уязвимых ПК в начале ........ {s['vulnerable_at_start']}")
    print(f"  Пик заражённых (E+I) ........ {s['peak_infected']} ПК на шаге {s['peak_step']}")
    print(f"  Заражались хотя бы раз ...... {s['ever_infected']} ПК ({_pct(s['ever_fraction'])})")
    if sim.model == "SIS":
        print(f"  Всего случаев заражения ..... {s['infections']}")
    print(f"  Половина сети заражена к .... {_fmt(s['half_network_step'])} шагу")
    print(f"  R0 по нулевому поколению .... {s['r0_gen0']:.2f}")
    print(f"  Попыток заражения ........... {s['attempts']}, заблокировано защитой: {s['blocked']}")
    ch = s["by_channel"]
    print(f"  Каналы заражения ............ по ЛВС: {ch['lan']}, через торрент: {ch['p2p']}, "
          f"из интернета: {ch['ext']}, нулевые: {ch['seed']}")
    if s["offline"]["hosts"]:
        print(f"  ПК вне ЛВС (автономные) ..... заражено {s['offline']['infected']} из {s['offline']['hosts']} "
              f"(только через торрент)")
    if s["p2p_users"]:
        print(f"  Торрент-пользователей ....... {s['p2p_users']}")
    print(f"  Инцидент обнаружен .......... шаг {_fmt(s['detected_at'])}, реагирование с шага {_fmt(s['response_at'])}")
    print("  По подсетям:")
    for row in s["subnets"]:
        print(f"    {row['subnet']:<14} заражено {row['infected']:>3} из {row['hosts']}")
    if args.log is not None:
        events = sim.events if args.log == 0 else sim.events[: args.log]
        print(f"\nЖурнал событий ({len(events)} из {len(sim.events)}):")
        for t, kind, text in events:
            print(f"  [шаг {t:>3}] {text}")
    if args.csv:
        _write_csv(args.csv, sim.history)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"scenario": sc, "summary": s, "history": sim.history}, f, ensure_ascii=False, indent=1)
        print(f"JSON сохранён: {args.json}")
    if args.plot:
        plot_run(sim.history, sim.n, args.plot, f"{v['name']}, {sim.model}, {net.topology}",
                 events={"обнаружение": s["detected_at"], "реагирование": s["response_at"]})
        print(f"График сохранён: {args.plot}")


def cmd_sweep(args) -> None:
    sc = _scenario(args)
    values = [x.strip() for x in args.values.split(",") if x.strip()]
    print(f"Сценарий: {sc['name']} | параметр {args.param} | {args.runs} прогонов на значение\n")
    rows = sweep(sc, args.param, values, args.runs)
    print(f"{'значение':>14} {'заражено, %':>14} {'P(вспышки)':>11} {'пик, ПК':>9} {'шаг пика':>9} "
          f"{'длит.':>7} {'R0':>6} {'блок. МСЭ':>10}")
    for r in rows:
        print(f"{str(r['value']):>14} {r['ever_mean'] * 100:>8.1f} ±{r['ever_std'] * 100:>4.1f} "
              f"{r['outbreak_prob'] * 100:>10.0f}% {r['peak_mean']:>9.1f} {r['peak_step_mean']:>9.1f} "
              f"{r['steps_mean']:>7.1f} {r['r0_mean']:>6.2f} {r['blocked_mean']:>10.1f}")
    print("\nP(вспышки) — доля прогонов, в которых заразилось не меньше 20 % сети.")
    if args.csv:
        _write_csv(args.csv, [{k: v for k, v in r.items() if k != "curve"} for r in rows])
    if args.plot:
        plot_sweep(rows, args.param, args.plot, f"{sc['name']}: влияние {args.param}")
        print(f"График сохранён: {args.plot}")


def cmd_theory(args) -> None:
    sc = _scenario(args)
    sim = make_simulation(sc, keep_events=False)
    th = theory.parameters(sim.net, sim.virus, sim.model, sim.params)
    print(f"Сценарий: {sc['name']} | модель {sim.model} | вирус: {sim.virus['name']}\n")
    print("Параметры однородной (среднеполевой) модели:")
    print(f"  Заражаемых ОС в сети ............... {th['targeted']} ПК")
    print(f"  Можно заразить всего .............. {th['susceptible_total']} ПК "
          f"(по ЛВС и/или через торрент)")
    print(f"  Главный канал ..................... {th['main_channel']}")
    print(f"  Скорость лечения g ................. {th['gamma_eff']:.3f} (средняя длительность заражения "
          f"{_fmt(1 / th['gamma_eff'] if th['gamma_eff'] else math.inf)} шагов)")
    print(f"  β по ЛВС .......................... {th['beta_lan']:.3f}")
    print(f"  β через торрент ................... {th['beta_p2p']:.3f}  (торрент-пользователей: {th['p2p_users']})")
    print(f"  β суммарно ........................ {th['beta_eff']:.3f}")
    print(f"  R0 = β/g .......................... {_fmt(th['R0'])}")
    if th["patch_helps"]:
        print(f"  R0 без патчей ..................... {_fmt(th['R0_no_patch'])}")
        print(f"  Порог коллективного иммунитета .... {_pct(th['herd_immunity'])} заражаемых ПК (1 - 1/R0)")
    else:
        print("  Патчи не защищают (вектор не требует уязвимости) — решают осведомлённость и антивирус")
    if sim.model in ("SIR", "SEIR"):
        z = theory.final_size_sir(th["R0"])
        print(f"  Итоговый размер эпидемии (SIR) ..... {_pct(z)} заражаемых ≈ {z * th['susceptible_total']:.0f} ПК")
    mf = theory.mean_field(sim.net, sim.virus, sim.model, sim.params)
    sims = monte_carlo(sc, args.runs)
    agg = aggregate(sims)
    mc = mean_curves(sims)
    print(f"\nСравнение (агентная модель: среднее по {args.runs} прогонам):")
    mf_peak = max(r["E"] + r["I"] for r in mf)
    print(f"  {'':<28}{'однородная':>12}{'агентная':>12}")
    print(f"  {'Пик заражённых, ПК':<28}{mf_peak:>12.1f}{agg['peak_mean']:>12.1f}")
    print(f"  {'Заражено за эпидемию, ПК':<28}{mf[-1]['ever']:>12.1f}{agg['ever_mean'] * sim.n:>12.1f}")
    print(f"  {'Длительность, шагов':<28}{mf[-1]['t']:>12}{agg['steps_mean']:>12.1f}")
    print("\nАгентная модель (среднее):")
    print(ascii_chart(mc, sim.n, keys=("S", "I", "R")))
    print("\nОднородная модель:")
    print(ascii_chart(mf, sim.n, keys=("S", "I", "R")))
    if args.plot:
        plot_run(mc, sim.n, args.plot, "Агентная модель (сплошные) и однородная (пунктир)", theory=mf)
        print(f"График сохранён: {args.plot}")


def cmd_build_web(args) -> None:
    from .webexport import build_web
    for path in build_web(ROOT):
        print(f"Записан {path}")


# ---------------------------------------------------------------- парсер
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m virus_lab",
                                description="Лаборатория по изучению распространения вирусов в сети из 100 ПК")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("-s", "--scenario", help="файл сценария (scenarios/*.json)")
        sp.add_argument("--seed", type=int, help="зерно генератора случайных чисел")
        sp.add_argument("--model", choices=list(MODELS), help="эпидемическая модель")
        sp.add_argument("--virus", choices=list(VIRUSES), help="тип вируса")
        sp.add_argument("--topology", choices=list(TOPOLOGIES), help="топология сети")
        sp.add_argument("--set", action="append", metavar="КЛЮЧ=ЗНАЧЕНИЕ",
                        help="изменить параметр, например --set network.patch_coverage=0.8")

    sp = sub.add_parser("inventory", help="список всех ПК виртуальной сети")
    common(sp)
    sp.add_argument("--csv", help="сохранить таблицу в CSV")
    sp.add_argument("-q", "--quiet", action="store_true", help="только сводка")
    sp.set_defaults(func=cmd_inventory)

    sp = sub.add_parser("viruses", help="описание вирусов и моделей")
    sp.set_defaults(func=cmd_viruses)

    sp = sub.add_parser("run", help="один прогон моделирования")
    common(sp)
    sp.add_argument("--log", type=int, nargs="?", const=0, help="вывести журнал событий (можно указать число строк)")
    sp.add_argument("--csv", help="сохранить динамику в CSV")
    sp.add_argument("--json", help="сохранить итоги и динамику в JSON")
    sp.add_argument("--plot", help="сохранить график (PNG, нужен matplotlib)")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("sweep", help="серия прогонов с перебором параметра")
    common(sp)
    sp.add_argument("--param", required=True, help="параметр, например network.patch_coverage или network.topology")
    sp.add_argument("--values", required=True, help="значения через запятую")
    sp.add_argument("--runs", type=int, default=30, help="прогонов на каждое значение (по умолчанию 30)")
    sp.add_argument("--csv", help="сохранить таблицу в CSV")
    sp.add_argument("--plot", help="сохранить график (PNG)")
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("theory", help="сравнение с аналитической моделью, R0, порог иммунитета")
    common(sp)
    sp.add_argument("--runs", type=int, default=30, help="прогонов агентной модели (по умолчанию 30)")
    sp.add_argument("--plot", help="сохранить график (PNG)")
    sp.set_defaults(func=cmd_theory)

    sp = sub.add_parser("build-web", help="обновить web/data.js и web/parity_fixture.js")
    sp.set_defaults(func=cmd_build_web)
    return p


def main(argv: list[str] | None = None) -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"Ошибка: {exc}") from exc
