#!/usr/bin/env python3
"""fix_nav_router_v24.py

Repair the main navigation router of the HackerAI local agent web UI.

Bugs fixed
----------
1. ``templates/index.html`` closed ``</main>`` and ``</div>`` (the .app grid
   wrapper) BEFORE the ``#view-missions`` section, so the Missions view lived
   outside the app grid entirely -> it stacked/overlapped and pushed content,
   instead of rendering as a full-screen view.
2. ``static/style.css`` had ``#view-chat{display:flex;...}`` with no ``.active``
   qualifier.  Because it is an ID selector it out-specified ``.view{display:none}``
   and forced the Command Center chat view to stay visible at all times, even
   while Settings / Live Activity / Missions were active  -> vertical overlap.
3. ``#view-input`` (Mouse & Keyboard) was a top-level ``.view`` that also
   contained ``#pane-input``.  ``openSettingsPane('input')`` activated the pane
   but never revealed its parent view, so the Settings sub-tab rendered blank.

The script is idempotent-ish and refuses to run if the expected anchors are
missing.  It writes timestamped ``.bak_router_*`` backups first.
"""

import datetime
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
IDX = os.path.join(ROOT, "templates", "index.html")
CSS = os.path.join(ROOT, "static", "style.css")

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def backup(path):
    dst = "{}.bak_router_{}".format(path, STAMP)
    shutil.copy2(path, dst)
    return dst


def find(lines, needle, start=0, what=None):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i
    raise SystemExit("ANCHOR NOT FOUND: {} ({!r})".format(what or needle, needle))


def main():
    with open(IDX, "r", encoding="utf-8") as fh:
        lines = fh.read().split("\n")

    before = len(lines)

    # ---------------------------------------------------------------
    # FIX 1: move </main> + </div> (close <main> and .app) to AFTER the
    #        missions </section>, so #view-missions is a child of <main>.
    # ---------------------------------------------------------------
    mi = find(lines, "MISSION CONSOLE VIEW", what="missions comment")

    # Scan upward for the </main> and </div> that close the app grid. They sit
    # immediately before the missions comment (only blank lines between).
    j = mi - 1
    while lines[j].strip() == "":
        j -= 1
    assert lines[j].strip() == "</div>", "expected </div> before missions, got: " + lines[j]
    div_i = j
    k = div_i - 1
    while lines[k].strip() == "":
        k -= 1
    assert lines[k].strip() == "</main>", "expected </main> before </div>, got: " + lines[k]
    main_i = k

    del lines[main_i:div_i + 1]           # remove </main> ... </div>

    # now re-find missions closing </section> (the one before the New Campaign modal)
    nc = find(lines, "New Campaign modal", what="new-campaign modal comment")
    s = nc - 1
    while lines[s].strip() == "":
        s -= 1
    assert lines[s].strip() == "</section>", "expected missions </section>, got: " + lines[s]

    close_block = ["", "  </main>", "</div>"]
    lines[s + 1:s + 1] = close_block

    # ---------------------------------------------------------------
    # FIX 3: relocate #view-input (Mouse & Keyboard) into #view-settings
    #        as a real .settings-pane so sub-tab routing works.
    # ---------------------------------------------------------------
    sec_i = find(lines, 'id="view-input"', what="view-input section")
    assert lines[sec_i].strip().startswith("<section"), lines[sec_i]

    # a preceding comment + blank line sit above the section
    ci = sec_i
    while lines[ci - 1].strip() == "" or lines[ci - 1].strip().startswith("<!--"):
        ci -= 1
    # ci now points at the first line of that comment/blank run

    ei = sec_i
    while lines[ei].strip() != "</section>":
        ei += 1

    inner = lines[sec_i + 1:ei]           # the pane <div id="pane-input"> ... </div>

    # sanity: inner must start with the pane div and end with its </div>
    assert 'id="pane-input"' in inner[0], "pane-input not directly inside view-input: " + inner[0]
    assert inner[-1].strip() == "</div>", "unexpected view-input tail: " + inner[-1]

    del lines[ci:ei + 1]                  # drop comment/blank + whole section

    # insert as a settings pane inside #view-settings, before its closing tag
    ss = find(lines, 'id="view-settings"', what="view-settings section")
    se = ss
    while lines[se].strip() != "</section>":
        se += 1

    insert = [""] + ["      <!-- Mouse & Keyboard live control (settings pane) -->"] + inner
    lines[se:se] = insert

    with open(IDX, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))

    # ---------------------------------------------------------------
    # FIX 2: scope the unconditional #view-chat display rule to .active
    # ---------------------------------------------------------------
    with open(CSS, "r", encoding="utf-8") as fh:
        css = fh.read()

    old_chat = ("#view-chat{\n"
                "  display:flex; flex-direction:column; justify-content:space-between;\n"
                "}")
    new_chat = ("#view-chat.active{\n"
                "  display:flex; flex-direction:column; justify-content:space-between;\n"
                "}")
    if old_chat in css:
        css = css.replace(old_chat, new_chat, 1)
        css_fix2 = "changed"
    elif new_chat in css:
        css_fix2 = "already applied"
    else:
        raise SystemExit("ANCHOR NOT FOUND: #view-chat display block in style.css")

    # ---------------------------------------------------------------
    # FIX 2b: harden the router - exactly one full-screen view at a time
    # ---------------------------------------------------------------
    hardening = """

/* ============================================================
   v24 NAV ROUTER HARDENING — exactly one full-screen view at a time
   (appended last so it wins the cascade).
   - every top-level .view fills the main pane and scrolls internally
   - a .view that is not .active can never be painted (kills the old
     unconditional #view-chat display:flex overlap bug for good)
   ============================================================ */
.main > .view{flex:1 1 auto; min-height:0; min-width:0; width:100%}
.view:not(.active){display:none !important}
#view-chat:not(.active){display:none !important}
"""
    marker = "v24 NAV ROUTER HARDENING"
    if marker not in css:
        if not css.endswith("\n"):
            css += "\n"
        css += hardening
        css_fix_h = "added"
    else:
        css_fix_h = "already present"

    with open(CSS, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(css)

    print("OK")
    print("  index.html  lines: {} -> {}".format(before, len(lines)))
    print("  css #view-chat scope: {}".format(css_fix2))
    print("  css router hardening: {}".format(css_fix_h))


if __name__ == "__main__":
    b1 = backup(IDX)
    b2 = backup(CSS)
    print("backups:")
    print("  " + b1)
    print("  " + b2)
    main()
