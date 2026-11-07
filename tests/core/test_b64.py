import pytest

from tba_core.b64 import b64url_decode, b64url_encode


def test_roundtrip_without_padding():
    data = bytes(range(16))
    s = b64url_encode(data)
    assert s == "AAECAwQFBgcICQoLDA0ODw"
    assert b64url_decode(s) == data


@pytest.mark.parametrize("bad", ["a+b", "a/b", "ab==", "a b", "a"])
def test_rejects_invalid(bad):
    with pytest.raises(ValueError):
        b64url_decode(bad)
