#!/usr/bin/env python3
"""Fix static/style.css to satisfy the Phase 1-3 dock-layering contract:
1. .chat-log base padding -> 6px 4px 140px (140px bottom cushion).
2. Move the trailing @media-bearing sections (AGENT HERO -> EOF) BEFORE the
   PHASE 1 enforcement marker so no @media appears in the phase-1 tail.
"""
from pathlib import Path

CSS = Path("static/style.css")
orig = CSS.read_text(encoding="utf-8", newline="")

# ---- Fix 1: base .chat-log bottom cushion -------------------------------
count = orig.count("padding:6px 6px 22px")
print("occurrences of 'padding:6px 6px 22px':", count)
assert count == 1, "unexpected occurrence count"
orig = orig.replace("padding:6px 6px 22px", "padding:6px 4px 140px")

# ---- Fix 2: move hero/activity sections before PHASE 1 marker -----------
marker = "PHASE 1 - input dock flush against bottom status bar"
assert orig.count(marker) == 1, "PHASE 1 marker must appear exactly once"

phase1_idx = orig.index(marker)
hero_anno = orig.index("AGENT HERO VISUAL")
# walk back to the opening '/*' of the hero comment banner
block_start = orig.rindex("/*", 0, hero_anno)
mid = orig[phase1_idx:block_start]          # phase1..hero banner (stays after move)
tail = orig[block_start:]                    # hero banner..EOF (moves up)

new = orig[:phase1_idx].rstrip() + "\r\n\r\n" + tail.rstrip() + "\r\n\r\n" + mid

# safety: every "@media" must now precede the PHASE 1 marker
assert new.rfind("@media") < new.index(marker), "@media still after PHASE 1 marker"

CSS.write_text(new, encoding="utf-8", newline="")
print("style.css patched: base cushion 140px, @media relocated before PHASE 1")
