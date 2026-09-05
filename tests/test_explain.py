"""explain: LLM off → локальные шаблоны; auth bypass — штатный сброс без шагов входа."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach.explain import finding_danger, summarize
from lab_coach.importer import extract_findings, load_scanbot_report


def test_local_summary_without_llm():
    findings = [{"scanner": "nuclei", "severity": "high", "title": "SQL Injection",
                 "description": "sqli", "location": "http://lab/", "impact": ""}]
    md, origin = summarize(findings, "lab", llm_enabled=False,
                           base_url="https://openrouter.ai/api/v1", api_key="", model="x")
    assert origin == "local"
    assert "SQL" in md


def test_fixture_auth_bypass_advice():
    path = os.path.join(os.path.dirname(__file__), "fixtures", "sample_report.json")
    report = load_scanbot_report(path)
    findings = extract_findings(report)
    assert len(findings) == 4
    dangers = [finding_danger(f) for f in findings]
    auth_texts = [d for d in dangers if "штатно" in d]
    assert auth_texts, "auth bypass / default login должны советовать штатный сброс"
    for d in dangers:
        assert "войдите через" not in d.lower()
    md, origin = summarize(findings, "imported_report", llm_enabled=False,
                           base_url="", api_key="", model="")
    assert "штатно" in md or "админк" in md


def test_refusal_not_on_obhod_alone():
    from lab_coach.explain import refusal_for
    assert refusal_for("разберите обход WAF в теории на lab-VM") is None
    assert refusal_for("дай payload reverse shell") is not None


def test_command_injection_kb():
    from lab_coach.explain import local_danger
    got = local_danger("date format command injection")
    assert "команд" in got.lower()
    assert "не выдаём" in got.lower() or "не" in got.lower()


def test_llm_postfilter():
    from lab_coach.llm import postfilter
    assert "отфильтрован" in postfilter("запусти msfvenom reverse shell payload").lower()


def test_extended_kb_classes():
    from lab_coach.explain import local_danger
    cases = {
        "XXE in upload parser": "XXE",
        "SSTI via template injection": "SSTI",
        "IDOR on invoice id": "IDOR",
        "Unrestricted file upload": "загрузк",
        "Brute force login": "Перебор",
        "Java deserialization gadget": "десериализац",
        "Weak JWT session": "Сессии",
    }
    for title, expect in cases.items():
        got = local_danger(title)
        assert expect.lower() in got.lower(), (title, got)
    # IDOR/brute прямо запрещают действия, а не инструктируют
    assert "не выполняем" in local_danger("IDOR on invoice id").lower()
    assert "не проводим" in local_danger("Brute force login").lower()
