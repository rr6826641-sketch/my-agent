"""Hypothesis-Driven Vulnerability Discovery Engine.

Instead of generic pattern scanning, this engine reasons about WHERE a
target's logic is most likely to fail: state flaws, race conditions,
authentication/authorization bypasses and multi-step business-logic
errors.

  tool_generate_security_hypotheses(target_scope, attack_surface_json)
      -> ranked structured hypothesis objects:
         { hypothesis_id, vulnerability_type, target_component,
           logic_reasoning, proposed_test_strategy, confidence_score }

Feed it code snippets, endpoint routes and enumerated services collected
during recon. The engine reasons about semantics (ownership checks,
state machines, request sequences, idempotency, trust boundaries) -
never surface patterns alone. Confidence rises with distinct semantic
signal hits and with code evidence in the input.
"""

import hashlib
import json
import re

MIN_CONF = 0.35
MAX_CONF = 0.92
SIGNAL_WEIGHT = 0.14
CODE_BONUS = 0.08
BASE_CONFS = {"state_flaw": 0.40, "race": 0.45, "session": 0.42}
DEFAULT_MAX = 8
HARD_CAP = 15

# Each rule reasons about a CLASS of logic failure. Signals are semantic
# hints (state, sequences, one-time resources, identity boundaries).
_RULES = [
    {
        "id": "state_flaw",
        "type": "Broken state transition / invalid state reachability",
        "signals": ("cart checkout order status approve pending settle "
                    "invoice subscription trial quota inventory stock "
                    "balance ledger activate flag").split(),
        "logic": (
            "Tracks mutable lifecycle state. If transitions are not "
            "enforced server-side as a strict sequence (e.g. pending -> "
            "paid -> fulfilled), an attacker can replay or reorder "
            "transitions to reach an invalid state the system still "
            "honors - bypassing payment, approval or consumption limits."),
        "strategy": (
            "Enumerate every state-transition endpoint; walk the happy "
            "path once and capture requests; then replay and REORDER the "
            "captured transitions (skip/duplicate steps) and check "
            "whether the server accepts an out-of-order or repeated "
            "transition it should reject."),
    },
    {
        "id": "race",
        "type": "Race condition / non-atomic check-then-act",
        "signals": ("coupon redeem transfer withdraw otp one-time reward "
                    "claim credit gift points refund vote limit").split(),
        "logic": (
            "Consumes a limited resource or one-time token. If the "
            "check-then-act window is not atomic under concurrency, "
            "parallel requests can all observe the pre-consumption state "
            "and each complete the action (double-spend / multiple "
            "redemption)."),
        "strategy": (
            "Capture one valid request, then send N concurrent copies "
            "(thread burst or HTTP/2 single-packet attack); count "
            "successful applications. Repeat with 5-50ms staggering to "
            "defeat coarse locks, and test cross-session parallelism."),
    },
    {
        "id": "authz",
        "type": "Authentication/authorization bypass (IDOR / missing object-level check)",
        "signals": ("user_id account_id profile invoice download export "
                    "admin internal attachment document message record "
                    "order_id").split(),
        "logic": (
            "Dereferences an identifier or privileged boundary. If "
            "authorization is enforced at the UI/route layer but the "
            "object lookup itself never checks the requesting principal's "
            "ownership/role, identifier shifting grants cross-principal "
            "read/write."),
        "strategy": (
            "Provision two accounts (A low-priv, B high-priv); as A, "
            "request B's objects by incrementing/decrementing ids and by "
            "substituting guids; also mutate the verb (GET<->POST), API "
            "version path and content-type to bypass filter-level checks."),
    },
    {
        "id": "multi_step",
        "type": "Multi-step business-logic error (flow reorder / step skip)",
        "signals": ("checkout shipping billing confirm next review "
                    "complete finalize submit verify step flow wizard "
                    "reset recover").split(),
        "logic": (
            "Belongs to a sequenced flow. If later steps re-trust earlier "
            "assertions (computed price, step flag, verification status) "
            "from client-held data instead of server-side session state, "
            "an attacker can skip or reorder steps so the enforced "
            "controls never run."),
        "strategy": (
            "Capture the full request sequence; then submit the final "
            "step directly, replay step 2 with step 3 data, and mutate "
            "step-carried values (amount, price, step flag) mid-flow; "
            "verify whether the server re-derives state or trusts input."),
    },
    {
        "id": "mass_assign",
        "type": "Client-trusted data / mass-assignment & price tampering",
        "signals": ("role price amount quantity discount email verified "
                    "is_admin hidden token signature serialized "
                    "cookie").split(),
        "logic": (
            "Likely binds request-controlled fields into domain objects "
            "or re-derives authoritative values from client input. If "
            "writable attributes (role, price, verified flags, ids) are "
            "accepted wholesale, identity and economics flip client-side."),
        "strategy": (
            "Inject suspected attributes into legitimate requests "
            "(role=admin, price=0.01, verified=true, user_id=<other>) via "
            "body, query and JSON alternates; compare persisted state and "
            "subsequent privileged behavior."),
    },
    {
        "id": "session",
        "type": "Authentication state confusion / verification-skip",
        "signals": ("login password token otp 2fa remember cookie jwt "
                    "impersonate email confirm signup verify").split(),
        "logic": (
            "Manipulates authentication identity state. If pre-auth and "
            "post-auth tokens share a namespace, or verification tokens "
            "carry a single claim (user only, no action/expiry binding), "
            "a step satisfied in one context can be honored in another - "
            "skipping MFA or account verification."),
        "strategy": (
            "Interleave flows: begin a password reset as user A, consume "
            "the token in user B's context; call post-2FA endpoints "
            "directly mid-flow; replay step tokens across sessions and "
            "check verification markers."),
    },
]

_CODE_HINT = re.compile(
    r"[{};()=<>]|def |await |SELECT|UPDATE|INSERT|return |=>|function")


def _parse_surface(attack_surface_json):
    """Parse attack-surface input; None signals invalid JSON text."""
    if attack_surface_json is None:
        return []
    if isinstance(attack_surface_json, (list, dict)):
        return attack_surface_json
    text = (attack_surface_json or "").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            decoded, _ = json.JSONDecoder().raw_decode(text)
            return decoded
        except (json.JSONDecodeError, ValueError):
            return None


def _iter_items(data):
    """Yield (raw_item, text_blob, component_label) per surface item."""
    if isinstance(data, dict):
        data = [data]
    for item in data:
        if isinstance(item, str):
            yield item, item, item.strip()[:120]
        elif isinstance(item, dict):
            blob = json.dumps(item, ensure_ascii=False, default=str)
            label = (item.get("route") or item.get("path")
                     or item.get("url") or item.get("service")
                     or item.get("name") or item.get("component"))
            label = str(label) if label else (
                (blob[:48] + "...") if len(blob) > 48 else blob)
            yield item, blob, label


def _code_present(raw_item):
    """True when the item carries code evidence (snippet or syntax)."""
    if isinstance(raw_item, dict):
        if any(k in raw_item for k in ("code", "snippet")):
            return True
        # plain JSON syntax ({, ") is not code evidence; inspect values only
        raw = " ".join(str(v) for v in raw_item.values()
                       if isinstance(v, str))
    else:
        raw = str(raw_item)
    if re.search(r"def |=>|function\s*\(", raw):
        return True
    return bool(_CODE_HINT.search(raw))


def _hypothesis_id(scope, component, rule_id):
    digest = hashlib.sha1(
        ("%s|%s|%s" % (scope, component, rule_id))
        .encode("utf-8", "replace")).hexdigest()[:8]
    return "HYP-%s" % digest


def _confidence(rule_id, distinct_hits, code_present):
    base = BASE_CONFS.get(rule_id, 0.32)
    conf = base + distinct_hits * SIGNAL_WEIGHT
    if code_present:
        conf += CODE_BONUS
    return round(max(MIN_CONF, min(MAX_CONF, conf)), 2)


def generate_security_hypotheses(target_scope, attack_surface_json,
                                 max_hypotheses=8):
    """Reason over enumerated attack surface and derive logic-flaw hypotheses.

    Args:
        target_scope: engagement target (domain/URL/app name) for labeling.
        attack_surface_json: JSON list/dict/text of endpoints, routes,
            code snippets or services gathered during recon.
        max_hypotheses: cap on returned hypotheses (1-15, default 8).

    Returns:
        JSON string: {"target_scope", "hypothesis_count", "hypotheses":
        [{hypothesis_id, vulnerability_type, target_component,
        logic_reasoning, proposed_test_strategy, confidence_score}]}.
        Each hypothesis reasons about a logic failure class (state flaw,
        race, authz bypass, multi-step error) - never a surface pattern.
    """
    scope = (target_scope or "").strip() or "(unspecified scope)"
    data = _parse_surface(attack_surface_json)
    if data is None:
        return json.dumps({
            "error": "attack_surface_json is not valid JSON. Pass a JSON "
                     "list of endpoint/code/service objects or JSON text.",
            "example": '[{"route": "/api/orders/123", "method": "GET", '
                       '"code": "order = db.get(id)"}]',
        })

    try:
        cap = int(max_hypotheses)
    except (TypeError, ValueError):
        cap = DEFAULT_MAX
    cap = max(1, min(cap, HARD_CAP))

    hypotheses = []
    seen = set()
    for raw_item, blob, label in _iter_items(data):
        if not blob:
            continue
        code_present = _code_present(raw_item)
        for rule in _RULES:
            hits = [s for s in rule["signals"] if s in blob]
            if not hits:
                continue
            key = (rule["id"], label.lower())
            if key in seen:
                continue
            seen.add(key)
            hypotheses.append({
                "hypothesis_id": _hypothesis_id(scope, label, rule["id"]),
                "vulnerability_type": rule["type"],
                "target_component": label,
                "logic_reasoning": "Signals observed: %s. %s" % (
                    ", ".join(hits[:6]), rule["logic"]),
                "proposed_test_strategy": rule["strategy"],
                "confidence_score": _confidence(
                    rule["id"], len(hits), code_present),
            })
            if len(hypotheses) >= cap:
                break
        if len(hypotheses) >= cap:
            break

    if not hypotheses:
        return json.dumps({
            "target_scope": scope,
            "hypothesis_count": 0,
            "note": ("no logic-flaw hypotheses derivable from this input. "
                     "Feed stateful descriptions (carts, transfers, resets, "
                     "ownership checks, request sequences) or code snippets "
                     "- recon-only output rarely supports reasoning."),
        })

    return json.dumps({
        "target_scope": scope,
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "note": ("confidence_score reflects reasoning strength from input "
                 "evidence - every hypothesis is UNTESTED until validated "
                 "via its proposed_test_strategy."),
    })


def tool_generate_security_hypotheses(target_scope="", attack_surface_json="",
                                      max_hypotheses=8):
    """Tool wrapper: generate logic-flaw hypotheses, render as ranked text."""
    raw = generate_security_hypotheses(target_scope, attack_surface_json,
                                       max_hypotheses)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if "hypotheses" not in data:
        return json.dumps(data, indent=2)
    lines = ["Security hypotheses for %s (%d derived, UNTESTED):"
             % (data.get("target_scope") or "(scope)",
                len(data["hypotheses"]))]
    lines.append("")
    for h in sorted(data["hypotheses"],
                    key=lambda x: -x["confidence_score"]):
        lines.append("## %s  [confidence %.2f]  %s"
                     % (h["hypothesis_id"], h["confidence_score"],
                        h["vulnerability_type"]))
        lines.append("component: %s" % h["target_component"])
        lines.append("reasoning: %s" % h["logic_reasoning"])
        lines.append("test plan: %s" % h["proposed_test_strategy"])
        lines.append("")
    return "\n".join(lines)
