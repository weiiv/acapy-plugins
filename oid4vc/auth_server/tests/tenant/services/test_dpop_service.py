from types import SimpleNamespace
from unittest.mock import Mock

from tenant.services import dpop_service


def test_disabled_dpop_does_not_emit_nonce_with_configured_secret(monkeypatch):
    get_validator = Mock()
    monkeypatch.setattr(dpop_service.settings, "DPOP_ENABLED", False)
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "secret")
    monkeypatch.setattr(dpop_service, "_get_validator", get_validator)

    assert dpop_service.get_dpop_nonce() is None
    get_validator.assert_not_called()


def test_enabled_dpop_emits_configured_nonce(monkeypatch):
    nonce_generator = Mock()
    nonce_generator.next.return_value = "nonce"
    monkeypatch.setattr(dpop_service.settings, "DPOP_ENABLED", True)
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "secret")
    monkeypatch.setattr(
        dpop_service,
        "_get_validator",
        Mock(return_value=SimpleNamespace(nonce_generator=nonce_generator)),
    )

    assert dpop_service.get_dpop_nonce() == "nonce"
