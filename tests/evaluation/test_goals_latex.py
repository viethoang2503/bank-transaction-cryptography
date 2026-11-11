from evaluation.expected import EXPECTED
from evaluation.goals import GOALS, goal_holds
from evaluation.latex import goals_table, scenarios_table


def test_goals_from_expected_matrix():
    holds = {g: {m: goal_holds(EXPECTED, m, ids) for m in ("baseline", "hmac", "sig", "sig_blind")}
             for g, (_, ids) in GOALS.items()}
    assert holds["G1"] == {"baseline": False, "hmac": True, "sig": True, "sig_blind": True}
    assert holds["G5"] == {"baseline": False, "hmac": False, "sig": True, "sig_blind": True}
    assert holds["G6"] == {"baseline": False, "hmac": False, "sig": True, "sig_blind": True}
    assert holds["G7"] == {"baseline": False, "hmac": True, "sig": True, "sig_blind": False}


def test_latex_tables_render():
    t = scenarios_table(EXPECTED)
    assert r"\begin{tabularx}{\linewidth}" in t and "S2a" in t and r"sig\_blind" in t and r"\xmark" in t
    g = goals_table(EXPECTED)
    assert "G7" in g and r"\cmark" in g
    # sig_blind evidence must carry the spec's asterisk and its note.
    for table, row_id in ((t, "S11"), (g, "G6")):
        row = next(line for line in table.splitlines() if line.startswith(row_id + " "))
        assert row.rstrip(" \\").endswith(r"\cmark$^{*}$")
        assert "device signed, not that the user saw" in table
