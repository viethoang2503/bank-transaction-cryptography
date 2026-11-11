import pytest

from evaluation.expected import EXPECTED
from evaluation.outcomes import MODES
from evaluation.scenarios import SCENARIOS


def test_registry_matches_expected():
    assert list(SCENARIOS) == list(EXPECTED)


@pytest.mark.parametrize("sid", list(EXPECTED))
@pytest.mark.parametrize("mode", MODES)
def test_scenario_outcome(tmp_path, sid, mode):
    _, fn = SCENARIOS[sid]
    assert fn(mode, tmp_path) == EXPECTED[sid][mode]
