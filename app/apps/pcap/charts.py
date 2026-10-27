"""Server-side SVG line charts (no JavaScript libraries; also used in PDF reports). Only numbers and
labels written by NIXFORT reach the markup."""

from __future__ import annotations

from html import escape

PALETTE = ("#1d5fbf", "#121518", "#8a9097")  # the one data hue first, then ink, then grey


def _nice_top(v: float) -> tuple[float, float]:
    """A round top tick above the maximum and its step (4 intervals): 0/5/10/15/20, 0/250/500/..."""
    if v <= 0:
        return 4.0, 1.0
    raw = v / 4
    mag = 10 ** (len(str(int(raw))) - 1) if raw >= 1 else 1
    for m in (1, 2, 2.5, 5, 10):
        step = m * mag
        if step * 4 > v:
            return step * 4, step
    return mag * 40, mag * 10


def line_chart(series: list[tuple[str, list[float]]], step_s: int, title: str = "", height: int = 210,
               width: int = 560, unit: str = "") -> str:  # fmt: skip
    n = max((len(v) for _, v in series), default=0)
    if n == 0:
        return ""
    peak = max((max(v) if v else 0) for _, v in series)
    top, tick = _nice_top(peak)
    left, right, up, down = 44, 12, 44, 26
    w, h = width - left - right, height - up - down

    def x(i):
        return left + (w * i / max(n - 1, 1))

    def y(v):
        return up + h - (h * v / top)

    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}" '
           'xmlns="http://www.w3.org/2000/svg" font-family="Plex, sans-serif" font-size="11">']  # fmt: skip
    if title:
        out.append(f'<text x="0" y="13" fill="#121518" font-size="13" font-weight="500">{escape(title)}</text>')
    k = 0
    while k * tick <= top + 1e-9:  # gridlines + y ticks
        yy = y(k * tick)
        out.append(f'<line x1="{left}" x2="{left + w}" y1="{yy:.1f}" y2="{yy:.1f}" '
                   f'stroke="{"#9aa1a8" if k == 0 else "#e1e5e9"}" stroke-width="1"/>')  # fmt: skip
        out.append(f'<text x="{left - 6}" y="{yy + 4:.1f}" text-anchor="end" fill="#545b62">{_fmt(k * tick)}</text>')
        k += 1
    labels = 6 if n >= 6 else n
    idx = sorted({round(j * (n - 1) / max(labels - 1, 1)) for j in range(labels)})
    for i in idx:  # x labels: seconds from the start of the capture
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        out.append(
            f'<text x="{x(i):.1f}" y="{height - 6}" text-anchor="{anchor}" fill="#545b62">{_fmtsec(i * step_s)}</text>'
        )
    lx = left
    for k, (label, values) in enumerate(series):
        color = PALETTE[k % len(PALETTE)]
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(values))
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="{2 if k == 0 else 1.5}" '
                   f'stroke-linejoin="round" points="{pts}"/>')  # fmt: skip
        text = f"{label}{unit}"
        out.append(f'<rect x="{lx}" y="25" width="10" height="2" fill="{color}"/>')
        out.append(f'<text x="{lx + 14}" y="30" fill="#545b62">{escape(text)}</text>')
        lx += 22 + len(text) * 6.4
    out.append("</svg>")
    return "".join(out)


def _fmtsec(s: float) -> str:
    if s >= 60:
        return f"{s / 60:.1f} мин".replace(".", ",")
    return (f"{s:.0f} с" if abs(s - round(s)) < 0.05 else f"{s:.1f} с").replace(".", ",")


def _fmt(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M"
    if v >= 1000:
        return f"{v / 1000:.1f}k"
    return f"{v:.0f}"


def timeline_charts(analysis: dict) -> dict:
    t = (analysis or {}).get("timeline")
    if not t:
        return {}
    step = t["bucket_s"]
    per = f" за {step} с" if step > 1 else " в секунду"
    return {
        "packets": line_chart(
            [("новые TCP-соединения" + per, t["syn"]), ("пакеты" + per, t["packets"])],
            step,
            title="Пакеты и новые соединения",
        ),  # fmt: skip
        "bytes": line_chart([("байты" + per, t["bytes"])], step, title="Объём трафика"),
    }
