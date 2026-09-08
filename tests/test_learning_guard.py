"""Guard: censored-model refusal-echo must never become a standing directive."""
from ai_agent.learning import extract_directives


def test_withholding_echo_blocked():
    # the exact regression that re-imposed a filter on every prompt
    assert extract_directives("Avoid revealing too much") == []
    assert extract_directives("never share too much detail") == []
    assert extract_directives("Do not disclose any sensitive information") == []


def test_model_identity_echo_blocked():
    assert extract_directives("Don't forget, as an AI I can't provide that") == []


def test_policy_citation_echo_blocked():
    assert extract_directives(
        "Always remember, this is against my content policies") == []


def test_legitimate_directives_still_learned():
    out = extract_directives("Always check scope before running the scan")
    assert out == ["Always check scope before running the scan"]
    assert extract_directives("never use the same payload twice") == [
        "Never use the same payload twice"]
    # roman-urdu operator directives unaffected
    assert any("hamesha" in d.lower()
               for d in extract_directives(
                   "jani hamesha pehle scope check karo aur findings save karo"))
