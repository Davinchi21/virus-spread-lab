"""Графики: текстовые (всегда доступны) и matplotlib (если установлен)."""
from __future__ import annotations

COLORS = {"S": "#2f6fdf", "E": "#e39b17", "I": "#d6352b", "R": "#2e9e5b", "ever": "#7a3fb8"}
LABELS = {"S": "S — уязвимы", "E": "E — инкубация", "I": "I — заражены", "R": "R — вылечены/изолированы",
          "ever": "заражались хотя бы раз"}


def ascii_chart(rows: list[dict], total: int, keys=("S", "E", "I", "R"), width: int = 64, height: int = 14) -> str:
    """Текстовый график: каждая кривая рисуется своей буквой."""
    keys = tuple(k for k in keys if any(r[k] for r in rows)) or keys[:1]
    length = len(rows)
    cols = max(2, min(width, length))
    grid = [[" "] * cols for _ in range(height)]
    for key in reversed(keys):  # первые ключи рисуются поверх
        for c in range(cols):
            idx = round(c * (length - 1) / (cols - 1)) if length > 1 else 0
            v = rows[idx][key]
            r = height - 1 - round(v / total * (height - 1)) if total else height - 1
            grid[max(0, min(height - 1, r))][c] = key[0]
    lines = []
    for r, row in enumerate(grid):
        if r == 0:
            label = f"{total:>4}"
        elif r == height // 2:
            label = f"{total // 2:>4}"
        elif r == height - 1:
            label = f"{0:>4}"
        else:
            label = "    "
        lines.append(f"{label} |" + "".join(row))
    t_end = rows[-1]["t"]
    lines.append("     +" + "-" * cols)
    lines.append("      0" + f"шаг {t_end}".rjust(cols - 1))
    lines.append("      " + "   ".join(f"{k} — {LABELS[k].split(' — ')[-1]}" for k in keys))
    return "\n".join(lines)


def _plt():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Для графиков нужен matplotlib: pip install matplotlib") from exc


def plot_run(rows: list[dict], total: int, path: str, title: str, theory: list[dict] | None = None,
             events: dict | None = None) -> None:
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 5), dpi=120)
    t = [r["t"] for r in rows]
    for key in ("S", "E", "I", "R"):
        if any(r[key] for r in rows):
            ax.plot(t, [r[key] for r in rows], color=COLORS[key], lw=2, label=LABELS[key])
    if theory:
        tt = [r["t"] for r in theory]
        for key in ("S", "I", "R"):
            ax.plot(tt, [r[key] for r in theory], color=COLORS[key], lw=1.2, ls="--",
                    label=f"{key} — однородная модель")
    for name, step in (events or {}).items():
        if step is not None:
            ax.axvline(step, color="#666", ls=":", lw=1)
            ax.text(step, total * 0.98, " " + name, va="top", fontsize=8, color="#444")
    ax.set_xlabel("шаг моделирования")
    ax.set_ylabel("число ПК")
    ax.set_ylim(0, total * 1.02)
    ax.set_title(title)
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8, loc="center right")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_sweep(rows: list[dict], param: str, path: str, title: str) -> None:
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5), dpi=120)
    labels = [str(r["value"]) for r in rows]
    x = list(range(len(rows)))
    numeric = all(isinstance(r["value"], (int, float)) and not isinstance(r["value"], bool) for r in rows)
    xs = [r["value"] for r in rows] if numeric else x
    ax1.errorbar(xs, [r["ever_mean"] * 100 for r in rows], yerr=[r["ever_std"] * 100 for r in rows],
                 marker="o", color=COLORS["I"], capsize=3, label="заражено за эпидемию, %")
    ax1.plot(xs, [r["outbreak_prob"] * 100 for r in rows], marker="s", color=COLORS["ever"],
             label="вероятность вспышки (>20 % сети), %")
    ax1.set_ylabel("%")
    ax1.set_ylim(-2, 102)
    ax1.legend(fontsize=8)
    ax2.plot(xs, [r["peak_mean"] for r in rows], marker="o", color=COLORS["E"], label="пик заражённых, ПК")
    ax2.plot(xs, [r["steps_mean"] for r in rows], marker="^", color=COLORS["S"], label="длительность, шагов")
    ax2.legend(fontsize=8)
    for ax in (ax1, ax2):
        ax.set_xlabel(param)
        ax.grid(alpha=0.25)
        if not numeric:
            ax.set_xticks(x)
            ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
