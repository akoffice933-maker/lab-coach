"""LLM_PROVIDER: openrouter default, ollama resolve, custom passthrough, probe без исключений."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach.config import load_settings
from lab_coach.llm import llm_configured, ollama_probe, resolve_endpoint


def _env(monkeypatch, **kw):
    for k in ("LLM_PROVIDER", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_API_KEY",
              "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "LLM_MODEL", "LLM_ENABLED"):
        monkeypatch.delenv(k, raising=False)
    for k, v in kw.items():
        monkeypatch.setenv(k, v)


def test_default_is_openrouter(monkeypatch):
    _env(monkeypatch)
    s = load_settings()
    base, key, model = resolve_endpoint(s)
    assert base == "https://openrouter.ai/api/v1"
    assert model == "openai/gpt-4o-mini"
    assert not llm_configured(s)  # ключа нет


def test_ollama_defaults_no_key_needed(monkeypatch):
    _env(monkeypatch, LLM_PROVIDER="ollama")
    s = load_settings()
    base, key, model = resolve_endpoint(s)
    assert base == "http://localhost:11434/v1"
    assert model == "qwen2.5:7b"
    assert llm_configured(s)  # ollama: ключ не нужен


def test_ollama_custom_values(monkeypatch):
    _env(monkeypatch, LLM_PROVIDER="ollama", OLLAMA_MODEL="llama3.1:8b",
         OLLAMA_BASE_URL="http://192.168.56.1:11434/v1")
    s = load_settings()
    base, _key, model = resolve_endpoint(s)
    assert base == "http://192.168.56.1:11434/v1"
    assert model == "llama3.1:8b"


def test_bad_provider_falls_back(monkeypatch):
    _env(monkeypatch, LLM_PROVIDER="skynet")
    assert load_settings().llm_provider == "openrouter"


def test_ollama_probe_never_raises():
    # Демона здесь нет — должен вернуть reachable=False, а не исключение.
    r = ollama_probe("http://127.0.0.1:9/v1", timeout=2)
    assert r == {"reachable": False, "models": []}
