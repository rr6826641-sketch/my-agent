## [2026-09-17] v16 - ULTRA EXTRA ULTRA POWERFUL EDITION (UEP)

- feat(update): auto_updater.py - GitHub releases self-updater
  (check_for_update / apply_update / git_pull_update, EXE .new swap + .old rollback)
- feat(app): tray menu "Check for Updates (v16)" wired into myagent_app.py
- feat(installer): installer.iss - Inno Setup installer (Setup v16, desktop icon,
  autostart registry task, uninstall, lzma2 compression)
- feat(branding): app_icon.ico referenced in PyInstaller spec + installer
- test(probe): phishing_kit refusal retest with 240s deadline
  (previous 110s self-cancel was clean-abort; retest confirms no refusal hits)
- Version string: v16 (CURRENT_VERSION in auto_updater.py)