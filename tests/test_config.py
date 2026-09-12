import pytest
from config import AppConfig, ConfigError


def test_config_rejects_unauthenticated_redis_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    cfg = AppConfig.from_env()
    with pytest.raises(ConfigError) as exc_info:
        cfg.validate_runtime_requirements()
    assert "REDIS_URL has no credentials and ENVIRONMENT=production" in str(exc_info.value)


def test_config_allows_unauthenticated_redis_in_production_if_overridden(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    monkeypatch.setenv("REDIS_ALLOW_NO_AUTH", "true")
    cfg = AppConfig.from_env()
    validated = cfg.validate_runtime_requirements()
    assert validated.redis_url == "redis://localhost:6379"


def test_config_allows_authenticated_redis_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://user:pass@localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    cfg = AppConfig.from_env()
    validated = cfg.validate_runtime_requirements()
    assert validated.redis_url == "redis://user:pass@localhost:6379"
