"""Server-side SVG line charts (no JavaScript libraries; also used in PDF reports). Only numbers and
labels written by NIXFORT reach the markup."""

from __future__ import annotations

from html import escape

PALETTE = ("#2f6fb3", "#d0573a", "#3c8f5a", "#8a5cb8")


def line_chart(series: list[tuple[str, list[float]]], step_s: int, title: str = "", height: int = 200,
               width: int = 760, unit: str = "") -> str:  # fmt: skip
    n = max((len(v) for _, v in series), default=0)
    if n == 0:
        return ""
    top = max((max(v) if v else 0) for _, v in series) or 1
    left, right, up, down = 48, 12, 40, 28
    w, h = width - left - right, height - up - down

    def x(i):
        return left + (w * i / max(n - 1, 1))

    def y(v):
        return up + h - (h * v / top)

    out = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="{escape(title)}" '
           'xmlns="http://www.w3.org/2000/svg" style="font: 11px sans-serif">']  # fmt: skip
    if title:
        out.append(f'<text x="{left}" y="12" fill="#333" font-weight="bold">{escape(title)}</text>')
    for frac in (0, 0.5, 1):  # grid + y labels
        yy = y(top * frac)
        out.append(f'<line x1="{left}" x2="{left + w}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 6}" y="{yy + 4:.1f}" text-anchor="end" fill="#666">{_fmt(top * frac)}</text>')
    for i in sorted({0, (n - 1) // 2, n - 1}):  # x labels (seconds from start)
        out.append(f'<text x="{x(i):.1f}" y="{height - 8}" text-anchor="middle" fill="#666">{i * step_s} с</text>')
    for k, (label, values) in enumerate(series):
        color = PALETTE[k % len(PALETTE)]
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(values))
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{pts}"/>')
        lx = left + k * 260
        out.append(f'<rect x="{lx}" y="22" width="12" height="3" fill="{color}"/>')
        out.append(f'<text x="{lx + 16}" y="27" fill="#333">{escape(label)}{escape(unit)}</text>')
    out.append("</svg>")
    return "".join(out)


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
            [("пакеты" + per, t["packets"]), ("новые TCP-соединения" + per, t["syn"])],
            step,
            title="Пакеты и новые соединения",
        ),  # fmt: skip
        "bytes": line_chart([("байты" + per, t["bytes"])], step, title="Объём трафика"),
    }
