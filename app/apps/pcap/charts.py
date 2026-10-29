"""Server-side SVG line charts (no JavaScript libraries). Only numbers and labels written by the
application reach the markup.

The chart keeps a constant text size at any width: labels and gridlines are placed in pixels and
percentages of the outer SVG, and only the data lines live in a stretched inner viewBox
(non-scaling strokes). A phone shows the same 12px labels as a desktop."""

from __future__ import annotations

from html import escape

PALETTE = ("#1f5aa8", "#14171a", "#8a9199")  # the data hue first, then ink, then grey
INK, MUTED, GRID, AXIS = "#14171a", "#636b73", "#e3e6ea", "#c3c9cf"


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


def line_chart(series: list[tuple[str, list[float]]], step_s: int, title: str = "", height: int = 200,
               unit: str = "") -> str:  # fmt: skip
    n = max((len(v) for _, v in series), default=0)
    if n == 0:
        return ""
    peak = max((max(v) if v else 0) for _, v in series)
    top, tick = _nice_top(peak)
    up, down = 48, 22  # title + legend above, x labels below
    h = height - up - down

    def y(v):
        return up + h - (h * v / top)

    out = [f'<svg class="chart" width="100%" height="{height}" role="img" aria-label="{escape(title)}" '
           f'xmlns="http://www.w3.org/2000/svg" font-family="Plex, sans-serif" font-size="12">']  # fmt: skip
    if title:
        out.append(f'<text x="0" y="14" fill="{INK}" font-size="13" font-weight="600">{escape(title)}</text>')
    lx = 0.0
    for k, (label, _values) in enumerate(series):  # legend
        color = PALETTE[k % len(PALETTE)]
        text = f"{label}{unit}"
        out.append(f'<rect x="{lx:.0f}" y="27" width="12" height="2" fill="{color}"/>')
        out.append(f'<text x="{lx + 16:.0f}" y="32" fill="{MUTED}">{escape(text)}</text>')
        lx += 32 + len(text) * 6.6
    k = 0
    while k * tick <= top + 1e-9:  # gridlines; the value sits on the line at the right edge
        yy = y(k * tick)
        out.append(f'<line x1="0" x2="100%" y1="{yy:.1f}" y2="{yy:.1f}" stroke="{AXIS if k == 0 else GRID}"/>')
        if k:
            out.append(f'<text x="100%" y="{yy - 4:.1f}" text-anchor="end" fill="{MUTED}">{_fmt(k * tick)}</text>')
        k += 1
    labels = 6 if n >= 6 else n
    idx = sorted({round(j * (n - 1) / max(labels - 1, 1)) for j in range(labels)})
    for i in idx:  # x labels: seconds from the start of the capture
        pct = 100 * i / max(n - 1, 1)
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        out.append(f'<text x="{pct:.2f}%" y="{height - 4}" text-anchor="{anchor}" fill="{MUTED}">'
                   f'{_fmtsec(i * step_s)}</text>')  # fmt: skip
    out.append(f'<svg x="0" y="{up}" width="100%" height="{h}" viewBox="0 0 1000 {h}" preserveAspectRatio="none" '
               'overflow="visible">')  # fmt: skip
    for k, (_label, values) in enumerate(series):
        color = PALETTE[k % len(PALETTE)]
        pts = " ".join(f"{1000 * i / max(n - 1, 1):.1f},{h - h * v / top:.1f}" for i, v in enumerate(values))
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="{2 if k == 0 else 1.5}" '
                   f'vector-effect="non-scaling-stroke" stroke-linejoin="round" points="{pts}"/>')  # fmt: skip
    out.append("</svg></svg>")
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
