import pytest


@pytest.fixture
def tmp(tmp_path):
    """Provide the legacy `tmp` fixture (a temp dir path string) used by
    the verify/reporting test suite, backed by pytest's tmp_path."""
    return str(tmp_path)


@pytest.fixture
def monkeypatch(monkeypatch):
    """Compatibility shim for legacy callable-style monkeypatch().

    pytest removed the callable form in v4 (2019); test_verify_arch.py
    still invokes monkeypatch(module, attr, value). Wrap the modern
    fixture so both styles work."""
    class _Patch:
        def __init__(self, inner):
            self._inner = inner

        def __call__(self, module, attr, value):
            self._inner.setattr(module, attr, value)

        def setattr(self, *a, **k):
            return self._inner.setattr(*a, **k)

        def delattr(self, *a, **k):
            return self._inner.delattr(*a, **k)

        def setenv(self, *a, **k):
            return self._inner.setenv(*a, **k)

        def delenv(self, *a, **k):
            return self._inner.delenv(*a, **k)

        def setitem(self, *a, **k):
            return self._inner.setitem(*a, **k)

        def delitem(self, *a, **k):
            return self._inner.delitem(*a, **k)

        def undo(self):
            return self._inner.undo()

    return _Patch(monkeypatch)
