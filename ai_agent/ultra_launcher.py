# ============================================================================
# ULTRA LAUNCHER v9.9 — drop-in bridge between the existing agent framework
# and the upgraded ULTRA modules.
#
#   from ultra_launcher import boot_ultra
#   gm = boot_ultra(project_dir="E:/HackerAI/my-agent")
#
# Bootstrap order:
#   1) UltraGM       -> uncensored persona + semantic lore + emotions + pacing
#   2) ObservationSuite -> screenshots / clipboard / window / keyboard log
#   3) (optional) existing framework Agent (mock-safe import)
# ============================================================================

import os
import sys


def boot_ultra(project_dir=".", state_dir=None, observations_dir=None):
    """Instantiate the full ULTRA stack. Returns a dict of handles."""
    proj = os.path.abspath(project_dir)
    data = state_dir or os.path.join(proj, "data")
    obs = observations_dir or os.path.join(proj, "observations")

    try:
        from .ultra_core import UltraGM
    except ImportError:
        from ultra_core import UltraGM
    gm = UltraGM(
        lore_path=os.path.join(data, "lore.db"),
        state_path=os.path.join(data, "state.json"),
        emotion_path=os.path.join(data, "emotions.json"),
    )

    try:
        from .capture_tools import ObservationSuite
    except ImportError:
        from capture_tools import ObservationSuite
    suite = ObservationSuite(out_dir=obs, screen_interval=30.0,
                             window_interval=5.0, keylog=True, clip=True,
                             screenshots=True, windows=True)

    handle = {"ultra_gm": gm, "observation_suite": suite,
              "data_dir": data, "obs_dir": obs}
    return handle


def start_suite(handle):
    handle["observation_suite"].start()
    return handle["observation_suite"]


def system_prompt(handle):
    return handle["ultra_gm"].build_system_prompt()


if __name__ == "__main__":
    h = boot_ultra()
    sp = system_prompt(h)
    print(sp[:600])
    print("\n--- ULTRA LAUNCHER OK (suite not started in CLI test) ---")