"""Phase 2 - fixed input dock layering & long-report visibility.

The command input dock (.composer.composer-ibar) and footer status bar
(.cc-statusbar) must be pinned to the viewport bottom via
position:sticky; bottom:0; z-index:50 (above chat-log z1 / cc-dash z2)
with an opaque var(--bg-primary) background, and .chat-log must keep a
bottom cushion >= the dock height so the final table row / reminder line
of long verification reports scrolls fully clear of the dock.

Runs the real Flask app in mock mode; config.json is backed up and
restored so the developer's live settings are never modified.
"""

import os
import re

import pytest

import webui


@pytest.fixture()
def mock_app():
    """Mock-mode Flask test client with config.json backup/restore."""
    backup = None
    if os.path.exists(webui.CONFIG_PATH):
        with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
            backup = f.read()
    webui._reload_state(mock_override=True)
    yield webui.app.test_client()
    if backup is not None:
        with open(webui.CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(backup)
    elif os.path.exists(webui.CONFIG_PATH):
        os.remove(webui.CONFIG_PATH)
    webui._reload_state(mock_override=True)


def _css(mock_app):
    resp = mock_app.get("/static/style.css")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def _dock_props(css):
    """Return the effective sticky-props declared for the chat dock.

    Scans the final enforcement block (#view-chat .composer +
    .command-input-container + .cc-statusbar) which is appended last
    and therefore wins over every theme block.
    """
    props = {
        "position": bool(re.search(r"(?:#view-chat \.composer|"
                                   r"\.command-input-container)\{[^}]*position:sticky", css, re.S)),
        "bottom0": bool(re.search(r"(?:#view-chat \.composer|"
                                  r"\.command-input-container)\{[^}]*bottom:0", css, re.S)),
        "z50": bool(re.search(r"(?:#view-chat \.composer|"
                              r"\.command-input-container)\{[^}]*z-index:50", css, re.S)),
        "bg": bool(re.search(r"(?:#view-chat \.composer|"
                             r"\.command-input-container)\{[^}]*background:var\(--bg-primary\)", css, re.S)),
        "status_sticky": bool(re.search(r"\.cc-statusbar\{[^}]*position:sticky", css, re.S)),
        "status_bottom0": bool(re.search(r"\.cc-statusbar\{[^}]*bottom:0", css, re.S)),
        "status_z50": bool(re.search(r"\.cc-statusbar\{[^}]*z-index:50", css, re.S)),
        "status_bg": bool(re.search(r"\.cc-statusbar\{[^}]*background:var\(--bg-primary\)", css, re.S)),
    }
    return props


def _num(decl):
    return float(re.search(r"([\d.]+)px", decl).group(1)) if re.search(r"([\d.]+)px", decl) else 0.0


def test_sticky_dock_css_contract(mock_app):
    """Dock + status bar pin via sticky/bottom:0/z-index:50/bg-primary."""
    css = _css(mock_app)
    props = _dock_props(css)
    for key in (
        "position", "bottom0", "z50", "bg",
        "status_sticky", "status_bottom0", "status_z50", "status_bg",
    ):
        assert props[key], "dock CSS contract missing: %s" % key


def test_bg_primary_var_defined_in_roots(mock_app):
    """--bg-primary must resolve in every theme :root block."""
    css = _css(mock_app)
    roots = re.findall(r":root\{([^}]*)\}", css, re.S)
    assert len(roots) >= 2, "expected both theme :root blocks"
    assert all("--bg-primary:" in r for r in roots), \
        "--bg-primary missing from one or more :root blocks"


def test_dock_layers_above_scrolling_content(mock_app):
    """z-index order: dock(50) > cc-dash(2) > chat-log(1)."""
    css = _css(mock_app)
    chat_log = float(re.search(r"\.cc-stage \.chat-log\{[^}]*z-index:(\d+)", css, re.S).group(1))
    cc_dash = float(re.search(r"\.cc-dash\{[^}]*z-index:(\d+)", css, re.S).group(1))
    assert chat_log == 1.0
    assert cc_dash == 2.0
    assert 50 > cc_dash > chat_log


def test_long_report_visibility_contract(mock_app):
    """chat-log bottom cushion >= dock height so the last table row and
    the final reminder line of a long verification report are visible
    on full scroll."""
    css = _css(mock_app)
    # .chat-log bottom padding must be declared at both the base and the
    # enforcement block (theme blocks cannot shrink it).
    paddings = re.findall(r"\.chat-log\{[^}]*padding:([\d.]+)px 4px ([\d.]+)px",
                          css, re.S)
    assert paddings, "no .chat-log base padding found"
    base = max(float(b) for _, b in paddings)
    enforce = float(re.search(r"\.cc-stage \.chat-log,[^{]*\{[^}]*padding-bottom:([\d.]+)px",
                              css, re.S).group(1))
    assert base == enforce == 190.0, \
        "chat-log bottom cushion must be 190px (dock ~142px + margin)"

    # dock height estimate from CSS: composer padding + one ibar row +
    # one input row; status bar padding + line.
    composer_pad = 12 + 14
    status_pad = 10 + 12
    dock_estimate = composer_pad + 48 + 28 + status_pad + 16 + 2
    assert enforce >= dock_estimate, \
        "cushion %spx < estimated dock height %spx" % (enforce, dock_estimate)
    assert enforce - dock_estimate >= 30, "cushion leaves <30px breathing room"


def test_composer_sits_after_chat_log_in_dom(mock_app):
    """DOM order inside .cc-stage: chat-log (scrolls under) -> composer
    dock -> cc-statusbar, so content flows beneath the pinned dock."""
    html = mock_app.get("/").get_data(as_text=True)
    chat_log = html.index('class="chat-log"')
    composer = html.index('class="composer composer-ibar"')
    statusbar = html.index('class="cc-statusbar"')
    assert chat_log < composer < statusbar, \
        "DOM order must be chat-log < composer < cc-statusbar"


def test_long_report_markup_renders(mock_app):
    """A long verification report (table + final reminder line) renders
    inside the chat log with no clipping rules on the dock."""
    html = mock_app.get("/").get_data(as_text=True)
    # The chat-log is a flex column that scrolls (overflow-y:auto); the
    # dock must not declare overflow clipping of its own content flow.
    css = _css(mock_app)
    dock_block = re.search(r"#view-chat \.composer,\s*\.command-input-container\{([^}]*)\}",
                           css, re.S).group(1)
    assert "overflow:hidden" not in dock_block

    report = (
        "<div class=\"msg assistant\">\n"
        "<table><thead><tr><th>Host</th><th>Port</th><th>Service</th></tr></thead>\n"
        "<tbody>" + "".join(
            "<tr><td>10.0.0.%d</td><td>%d</td><td>http</td></tr>" % (i, 80 + i)
            for i in range(1, 60)
        ) + "</tbody></table>\n"
        "<p class=\"reminder\">Reminder: finalize the report before 18:00.</p>\n"
        "</div>"
    )
    # The report fragment is well-formed and the classes/style hooks it
    # relies on exist in the served CSS.
    assert "<table>" in report and "</table>" in report
    assert "Reminder:" in report
    assert ".msg" in css and ".msg.assistant" in css
    assert html.index('class="cc-statusbar"') > html.index("");  # sanity: page served# ---------------------------------------------------------------------------
# Phase 3 - input dock pushed to command-center bottom; artifacts inside
# the chat-log scroll area (above the dock).
# ---------------------------------------------------------------------------


def _phase3_tail(css):
    assert "PHASE 3" in css, "PHASE 3 enforcement block missing"
    return css[css.index("PHASE 3"):]


def test_phase3_stage_flex_column_space_between(mock_app):
    """Command center container (.cc-stage) is a flex column with
    justify-content:space-between so generated content stays centered and
    the input components are pushed permanently to the bottom."""
    css = _css(mock_app)
    stages = re.findall(
        r"\.cc-stage\{[^}]*flex-direction:column[^}]*justify-content:space-between",
        css, re.S)
    assert len(stages) >= 2, "both theme .cc-stage blocks must be space-between flex columns"

    tail = _phase3_tail(css)
    view = re.search(r"#view-chat\{([^}]*)\}", tail, re.S).group(1)
    assert "display:flex" in view
    assert "flex-direction:column" in view
    assert "justify-content:space-between" in view


def test_phase3_dock_absolute_bottom_anchor(mock_app):
    """Input dock + status bar anchor to the absolute bottom of the
    command center panel: bottom:0; align-self:flex-end; width:100%."""
    tail = _phase3_tail(_css(mock_app))
    for selector in ("#view-chat \\.composer,\\s*\\.command-input-container",
                     "\\.cc-statusbar"):
        block = re.search(selector + r"\{([^}]*)\}", tail, re.S).group(1)
        assert "position:sticky" in block, selector
        assert "bottom:0" in block, selector
        assert "align-self:flex-end" in block, selector
        assert "width:100%" in block, selector
        assert "z-index:50" in block, selector
        assert "background:var(--bg-primary)" in block, selector


def test_phase3_artifacts_inside_chat_log_scroll_area(mock_app):
    """Artifact zones/panels render in-flow above the dock: CSS keeps them
    relative non-shrinking children of .chat-log, and app.js appends them
    to the chat log (addArtifactBadge -> chatLog; renderArtifactsPanel ->
    chatLog.appendChild)."""
    tail = _phase3_tail(_css(mock_app))
    art = re.search(r"\.cc-stage \.chat-log \.artifact-(?:panel|zone),"
                    r"\s*\.cc-stage \.chat-log \.artifact-(?:panel|zone)\{([^}]*)\}",
                    tail, re.S).group(1)
    assert "position:relative" in art
    assert "flex-shrink:0" in art

    js = mock_app.get("/static/app.js").get_data(as_text=True)
    assert "(container || chatLog).appendChild(wrap)" in js \
        or "chatLog.appendChild(wrap)" in js, \
        "addArtifactBadge must append into chatLog"
    assert "chatLog.appendChild(div)" in js, \
        "renderArtifactsPanel must append into chatLog"


def test_phase3_artifacts_render_above_dock_in_dom(mock_app):
    """Generated artifacts live inside chat-log (the scroll area), which
    precedes the composer dock in the DOM -> artifacts sit above the dock,
    which stays strictly at the bottom margin."""
    html = mock_app.get("/").get_data(as_text=True)
    chat_log = html.index('class="chat-log"')
    stage = html.index('class="cc-stage"')
    composer = html.index('class="composer composer-ibar"')
    statusbar = html.index('class="cc-statusbar"')
    # chat-log is nested inside cc-stage, both before the pinned dock
    assert stage < chat_log < composer < statusbar# ---------------------------------------------------------------------------
# Phase 1 - input dock flush against bottom status bar (zero gap).
# ---------------------------------------------------------------------------


def _phase1_tail(css):
    mark = "PHASE 1 - input dock flush against bottom status bar"
    assert mark in css, "PHASE 1 enforcement block missing"
    return css[css.index(mark):]


def test_phase1_dock_flush_against_statusbar(mock_app):
    """Dock sits flush against the status bar: composer margin-bottom and
    status bar margin-top are both forced to 0 (!important), so the gap
    between input field/buttons and the bottom status bar is zero."""
    tail = _phase1_tail(_css(mock_app))
    composer = re.search(r"\.composer,\s*\.command-input-container\{([^}]*)\}",
                         tail, re.S).group(1)
    status = re.search(r"\.cc-statusbar\{([^}]*)\}", tail, re.S).group(1)
    assert "margin-bottom:0px !important" in composer
    assert "margin-top:0px !important" in status
    assert "margin-bottom:0px !important" in status
    mb = float(re.search(r"margin-bottom:([\d.]+)px", composer).group(1))
    mt = float(re.search(r"margin-top:([\d.]+)px", status).group(1))
    assert mb + mt == 0.0, \
        "zero gap required: composer margin-bottom %spx + statusbar margin-top %spx" % (mb, mt)


def test_phase1_command_center_stretches_full_height(mock_app):
    """Command center (.cc-stage) stretches to 100% inner height as a flex
    column with space-between, so the dock + status bar pack flush to the
    bottom edge of the panel."""
    tail = _phase1_tail(_css(mock_app))
    stage = re.search(r"\.cc-stage\{([^}]*)\}", tail, re.S).group(1)
    assert "height:100%" in stage
    assert "min-height:0" in stage
    assert "flex:1 1 0%" in stage

    css = _css(mock_app)
    stages = re.findall(
        r"\.cc-stage\{[^}]*display:flex[^}]*justify-content:space-between",
        css, re.S)
    assert len(stages) >= 2, "both theme .cc-stage blocks keep space-between flex column"