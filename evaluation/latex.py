from .goals import GOALS, goal_holds
from .outcomes import GOOD, MODES, NA

HEADER = " & ".join(m.replace("_", r"\_") for m in MODES)
COLSPEC = "@{}lX" + "c" * len(MODES) + "@{}"
STAR = r"$^{*}$"
# Spec section 6: in sig_blind the signature proves the device signed, not that the user saw the transaction.
STARRED = {("S11", "sig_blind"), ("G6", "sig_blind")}
STAR_NOTE = (r"\par\smallskip{\footnotesize " + STAR + r" In \texttt{sig\_blind} the signature only proves "
             r"that the device signed, not that the user saw the transaction.\par}")


def _cell(value: str) -> str:
    if value == NA:
        return "--"
    return r"\cmark" if value in GOOD else r"\xmark"


def _table(first: str, second: str, rows: list[tuple[str, str, list[str]]]) -> str:
    lines = [rf"\begin{{tabularx}}{{\linewidth}}{{{COLSPEC}}}", r"\toprule",
             rf"{first} & {second} & {HEADER} \\", r"\midrule"]
    starred = False
    for rid, desc, cells in rows:
        marked = [c + STAR if (rid, m) in STARRED and c != "--" else c for m, c in zip(MODES, cells)]
        starred = starred or marked != cells
        lines.append(rf"{rid} & {desc} & {' & '.join(marked)} \\")
    lines += [r"\bottomrule", r"\end{tabularx}"]
    if starred:
        lines.append(STAR_NOTE)
    return "\n".join(lines) + "\n"


def scenarios_table(results: dict, titles: dict | None = None) -> str:
    titles = titles or {}
    rows = [(sid, titles.get(sid, ""), [_cell(row[m]) for m in MODES]) for sid, row in results.items()]
    return _table("ID", "Scenario", rows)


def goals_table(results: dict) -> str:
    rows = []
    for gid, (desc, ids) in GOALS.items():
        cells = []
        for m in MODES:
            holds = goal_holds(results, m, ids)
            cells.append("--" if holds is None else (r"\cmark" if holds else r"\xmark"))
        rows.append((gid, desc, cells))
    return _table("Goal", "Description", rows)
