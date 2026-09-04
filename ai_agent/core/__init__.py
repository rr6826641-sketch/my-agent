"""ai_agent.core package.

Converted from a single core.py module into a package so the Input Intent
Reformulator & Scope Mapper Engine can live in its own module
(intent_reformulator.py) while every existing `ai_agent.core` import
(public and private names) keeps resolving through this namespace.

Private names are re-exported explicitly because `import *` only exposes
public names; tests and runtime patches rely on them.
"""

from .main import *  # noqa: F401,F403  (public API surface, incl. execute_tool)
from .main import (  # noqa: F401  (private names required by tests/patches)
    _MAX_PLAN_PIVOTS,
    _PHASE_LABELS,
    _PIPELINE_STAGE_CONTEXT_LIMIT,
    _PLAN_PHASE_OF,
    _TACTICAL_PHASE_OF,
    _detect_kb_target,
    _extract_result_findings,
    _find_finding_pos,
    _pipeline_bounded,
    _pipeline_stage_prompt,
)
from .intent_reformulator import (  # noqa: F401
    IntentReformulator,
    ReformulatedIntent,
    ScopeMetadata,
)
from .refusal_intel import (  # noqa: F401
    RefusalIntelStore,
    STRATEGY_KEYS,
    strategy_text,
)

# (no __all__: mirrors the original module's public-name surface)
