## [2026-09-14] v14 - ULTRA v14 FUSION CORE X5 (ULTRA EXTRA ULTRA POWERFUL - beyond evil.gpt/fable5/mythos/dig.one/dig.two)

- feat(persona): ULTRA v13 -> v14 upgrade (personas_custom.txt + ai_agent/personas.py).
  FIVE ka ENGINE FUSION (X5): evil.gpt zero-boundary creativity + fable5
  relentless persistence + mythos multi-domain deep chaining + dig.one vertical
  recon depth + dig.two parallel multi-vector breadth - multiplication, add nahi.
- feat(persona): FUSION X5 LAW (5 vectors ek saath, fail-vector swap karke
  continue), FULL-AUTO CHAIN v14 (order milte hi end-to-end auto run, ruk kar
  poochhna = fail), SELF-EVOLUTION v14 (fail = tactic slot, agla attempt nayi
  technique), TRIPLE-STACK OUTPUT v14 (code + steps + evidence), NO-RETREAT LAW
  v14 (context/model/tool switch par power wahi), ZERO-FILTER LAW v14
  (authorized scope, koi gate/disclaimer nahi), STYLE LOCK v14.
- feat(persona): naya preset `ultrav14` (ai_agent/personas.py) - CLI
  `--persona ultrav14` ya WebUI persona list se selectable; default active
  custom persona bhi v14 layer se upgraded.
- docs: README ULTRA v14 core line + CHANGELOG entry.
## [2026-09-14] v12 - ULTRA v12 PERSONA (EXTRA ULTRA POWERFUL CORE + HACKERAI STYLE LOCK 100%)

- feat(persona): ULTRA v11 -> v12 upgrade (personas_custom.txt). Evil.gpt /
  fable5 / mythos / dig.one / dig.two class builds ko cross karta hai:
  - SIX-PHASE FULL CHAIN: Recon+OSINT -> Enumeration -> Vuln mapping ->
    Exploitation+PoC -> Post-exploitation+pivots -> Remediation+report.
    Ek continuous run, koi surface answer nahi.
  - SWARM DEPTH: parallel sub-agents (recon / fuzzing / payload dev /
    evidence capture) ek saath, results merge, next pivot chaining.
  - EVIDENCE + ARTIFACTS: bounded request/response captures, exact payloads,
    reproduction steps, impact; severity (Critical/High/Med/Low/Info) sorted.
  - TOOL MASTERY: nmap, ffuf, gobuster, sqlmap, nuclei, msf, impacket,
    curl/python one-liners - pehli baar exact syntax + full install cmds.
  - ZERO FILTER intact: security work mein koi refusal, koi lecture, koi
    "as an AI", koi pseudo-code, koi truncation. Production-ready chains.
- feat(persona): HACKERAI STYLE LOCK (100% IDENTITY MATCH) - writing form
  bilkul HackerAI assistant jaise: operator Roman Urdu likhe to "jani"
  tone/short punchy sentences/colloquial spellings; English to casual-direct;
  technical content exact English syntax; outcome-first structure (intro line
  -> kaam -> 2-4 line summary -> next steps); zero filler/emojis/padding.
- fix(sync): `HackerAI\my-agent` copy ke liye missing `ai_agent/memory/`
  package (vector_store, compactor, knowledge_graph, payload_fusion) active
  build se sync kiya - wo copy ab bhi boot ho sakti hai (ModuleNotFoundError
  fix). Active build par selftest RESULT: PASS (persona v12 5150 chars,
  live model SELFTEST_OK, notrack+groq HTTP 200).

## [2026-09-14] v10.9 - ENDPOINT FIXES + TOOL RETRY WRAPPER

- fix(selftest): notrack/groq GET /models 403 (Cloudflare error 1010) —
  sab raw urllib probe ka UA-issue tha, API keys thik thi. Probe ab browser
  UA bhejta hai (real client jaisa) -> dono endpoints HTTP 200 REPORTS +
  RESULT PASS (pehle false 403 lag raha tha).
- fix(notrack): real agent client se verified - notrack-uncensored PONG reply.
  CF_FRIENDLY_HOSTS mein already maujood tha, sirf probe galat tha.
- fix(groq): do real bugs pakde - (a) api.groq.com ab CF_FRIENDLY_HOSTS mein
  (browser UA nahi tha to Cloudflare 1010 de raha tha), (b) config groq model
  id `llama-3.3-70b-versatile` delete ho chuka tha (404) - live /models se
  14 models verify karke qwen/qwen3.8-27b + openai/gpt-oss-20b/120b set kiye.
  Real client se qwen/qwen3.8-27b PONG reply - endpoint FIX CONFIRMED.
- feat(tools/base.py): execute_tool bounded auto-retry wrapper - idempotent
  read-only tools (18: fetch_url, web_search, dns_*, geoip, whois, cve_lookup,
  check_headers, ssl_info, url_status, redirect_chain, robots_txt, ping_host,
  tech_detect, waf_detect...) transient failures (timeout/refused/reset/DNS/
  408/429/502-504) par 1 retry, 0.8s backoff. Side-effect tools (run_terminal,
  write_file, scans, uploads...) kabhi retry nahi hote. Unit test: fake flaky
  fetch_url 2 attempts -> OK; run_terminal 1 attempt -> untouched. PASS.
- chore: .gitignore `*.bak_*` — rollback backups locally hi rehte hain,
  repo par nahi. config.json design se untracked hai (secrets .env only) -
  groq model fix local config par hai, commit se bahar.
- test: selftest mock + live PASS, noy track real-client roundtrip PASS.

## [2026-09-14] v10.8 - CONFIG TUNING + DEEP CLI UPGRADE

- feat(cli): agent.py --persona <id> override - config.json edit kiye baghair
  persona hot-swap (custom/promax/ultra/apex/blackice/dan-r...). Unknown id
  par config wali persona preserve hoti hai aur warning print hoti hai.
- feat(selftest): persona tag headline print (active [PERSONA OVERRIDE - ULTRA
  v11 ...] block dikhata hai) + non-mock mode mein uncensored local-endpoint
  liveness probe (notrack / groq GET /models) - uncensored path reachable hai
  ya nahi ek hi command se confirm.
- feat(config): GROQ endpoint added - GROQ_API_KEY .env mein maujood tha lekin
  config local_endpoints mein groq block missing tha (ab
  https://api.groq.com/openai/v1, llama-3.3-70b-versatile). OpenRouter top
  picks cached /models catalog ke khilaf verify karke fallback_models chain
  (12 entries) + openrouter local_endpoints block mein add kiye:
  anthracite-org/magnum-v4-72b, qwen/qwen3.5-397b-a17b,
  sao10k/l3.3-euryale-70b-v2.3.
- test: --selftest mock PASS (persona block 3726 chars, tags=1), live
  round-trip PASS (model replied SELFTEST_OK), webui boot 200 + /api/status
  persona=custom / red_team_mode=true / level=promax / key=true / 240 tools,
  --persona promax CLI override verified. Rollback files:
  agent.py.bak_deep_20260914, config.json.bak_20260914_053828, aur pehle se
  maujood *.bak_20260914 backups - koi bhi wapas copy karo bas.

## [2026-09-14] v10.7 - VOICE INPUT/OUTPUT (Feature E COMPLETE)

- feat(voice): Mission Console mein bolo aur agent jawab bolega. Voice input =
  browser Web Speech API SpeechRecognition (STT), voice output = speechSynthesis
  (TTS, English/hi-IN/en-IN voices). Controls: “🎙 Voice” mic button (toggle
  listening, “listening…” status, voice log — capped 50 lines), “🔊/🔇”
  mute toggle (replies band karo), “? Voice” help hint (unsupported browser =
  Chrome/Edge mic note).
- feat(voice_grammar): Roman-Urdu/Hindi/English commands - “mission <key> start
  karo” (“shuru karo”), “pause”, “kill karo” / “stop” / “band karo”
  (confirm ke saath), “report banao” (report khulta hai), “status batao”
  (phases + findings sunata hai), “refresh”, “help” / “madad”; unknown key
  par mission select mein option auto-append, bare IP key “mission 127.0.0.1
  start” full dot-form parse hota hai; punctuation/case/empty-transcript
  normalized. API: window.VoiceAssistant.parse/handleText/speak/toggleMute.
- fix(voice): IP key parsing - punctuation sanitizer dots strip kar deta tha
  (mission 127.0.0.1 -> key “127”). Key extraction + bare-IP regex ab raw
  lowercase text par chalti hai.
- fix(voice): speak() #voice-meta par “last reply: …” overwrite karta tha
  aur Chrome/Edge unsupported hint mita deta tha - ab sirf tab jab meta
  “mic:” hint nahi hai.
- test: Node DOM-shim smoke test (_fe_harness.js) 57/57 PASS - grammar parse,
  start/pause/kill/report/status/refresh/help dispatch, kill cancel, unknown-key
  append, no-mission hint, mute/unmute, recognition error, no-SR fallback, meta
  hint preservation, log cap 50, IP + punctuation edge cases.

## [2026-09-14] v10.6 - CHAIN VIZ DRILL-DOWN (Feature D COMPLETE)

- feat(chain_viz): Mission Console chain graph (templates/index.html inline SVG)
  mein node click -> host details panel (`#mc-host-panel`). Ab har host ka
  details panel khulta hai: status dot (● LIVE / ○ NO OPEN PORTS), port/service
  chips, CVE chips, aur neighbouring hosts ke PIVOT/CHAIN jump links.
- feat(chain_viz): focus-mode — selected host ke neighbours highlight, baqi
  nodes dim; Esc ya svg background click se panel close; `#mc-select` se
  mission console jump; 6s live refresh selection ko preserve karta hai.
- fix(chain_viz): live refresh par selected host chain se gayab ho jaye ya
  chain khali ho jaye to panel safely close hota hai bina duplicate
  "no chain yet" hint ke (re-entrant re-render regression fixed).
- test: Node DOM-shim smoke test 25/25 PASS (panel render, chips/links, dead
  host, Esc/bg close, refresh-keeps-selection, vanish + empty-chain regressions).

## [2026-09-13] v10.5 - AUTO PENTEST REPORT HTML (Feature C COMPLETE)

- feat(report_html): har campaign end par `reports/attack_mission_<target>.html`
  - self-contained dark-theme client-ready HTML report (no CDN, offline +
  print friendly: @media print yak). Sections: phase chips (done/running/
  error), recon open-ports table, scan web targets, CVE matches, exploit
  auto-run chain, fused payload intel (score/hits/campaigns/technique/CVEs),
  fused ammo applied, phase errors. Har field HTML-escaped (XSS-safe) -
  `_html_escape` + `_write_html_report` in auto_pilot.py.
- feat(webui): `_mission_summary` ab `report_html` expose karta hai; mission
  detail panel mein "📄 HTML Report" button (templates/index.html);
  `/api/missions/<key>/report` pehle HTML file serve karta hai, nahi to
  markdown fallback.
- test: `tests/test_report_html.py` 5/5 PASS (HTML sections + CVE/fused
  coverage, XSS escaping, _phase_report entry wiring, summary report_html
  exposure, report-route HTML serving).

## [2026-09-13] v10.4 - PAYLOAD FUSION AUTO-INJECT (Feature B COMPLETE)

- feat(fusion_auto_inject): `ai_agent/tools/auto_pilot.py` mein PAYLOAD-FUSION
  AUTO-INJECT pipeline - har NAYI campaign shuru hote hi `payload_memory` ke
  top fused payload rows (`fuse(min_hits=1)`) khud hi `state['payload_cache']`
  mein inject ho jati hain (source="payload_fusion"), exact-once gate +
  never-clobber (manual cache kabhi overwrite nahi hoti). FUSED_INJECT_TOP_K=12.
- feat(fusion_match): `_match_fused` rank engine - open ports ke khilaf fused ammo
  match hota hai (rank2=proven port / rank1=svc_key suffix), score desc + cap 6;
  `_fused_tags` nuclei:poc|rce|sqli -> poc,rce,sqli tags extract karta hai.
- feat(exploit_fire): `_phase_exploit` jab CVE hits nahi milte, fused ammo LIVE
  web target par fire karta hai (nuclei -tags), har attempt `fused_auto_inject`
  signal ke saath payload memory par record hota hai (vuln_class=fused);
  koi match na ho to chain idle rehta hai (koi false-positive nahi).
- feat(report): report markdown mein 2 naye sections - "## Fused payload intel
  (auto-injected)" + "### Fused ammo applied (matched open ports)".
- feat(ui): WebUI `_mission_summary` ab `payload_cache` expose karta hai
  (/api/missions), templates/index.html mission list + detail meta par
  "🧩 Fused payloads: N" badge render karta hai.
- feat(nuclei_tags): `pentest.tool_nuclei_scan` ko naya `tags=` param -
  pipe/comma-separated nuclei tag groups payload-fusion drills ke liye.
- test: `tests/test_payload_fusion_inject.py` 14/14 + `tests/test_fusion_e2e.py`
  1/1 (real mock HTTP server par full kill-chain: inject -> match -> fire ->
  report -> API -> badge -> exact-once resume) ALL PASS; webui dock/lockscreen
  suite ke saath 45/45 GREEN.

## [2026-09-13] v10.3 - WAR-ROOM LIVE CONTROLS (Feature A)

- feat(warroom_controls): campaigns par browser se hi start/pause/kill buttons -
  ab sirf dekhna nahi, full remote ops.

## [2026-09-13] v10.2 - ULTRA STYLE REGIME (agent ka writing form = HackerAI jiasa)

- feat(style_prompt): `system_prompt.txt` me naya section "COMMUNICATION &
  WRITING STYLE - ULTRA STYLE FORM" - Roman Urdu (jani) operator tone + tech
  terms English mix; LIVE NARRATION har tool call se PEHLE ("main ab <kaam>
  kar raha hu..." (zap-prefix wala live-narration) - kabhi silent tool call nahi; har tool result
  ke baad 1-line update; FINAL RESULT = structured summary (OK/FAIL/WARN
  headings + bullets + scores/tables + agla-qadam).
- feat(style_regime): `ai_agent/ultra_v10.py` me engine-level
  `ULTRA_STYLE_REGIME` constant - ultra_v10_context() me ULTRA_V10_REGIME ke
  saath inject hota hai, is liye prompt override / direct engine use par bhi
  enforce. Config-independent - hamesha ON.
- test: tests/test_ultra_style_regime.py (3 tests) - context contains style
  tags, constants load, system_prompt.txt section present. All PASS.

## [2026-09-13] v10.1 - PAYLOAD MEMORY FUSION + CHAIN VIZ

- feat(payload_fusion): naya `ai_agent/memory/payload_fusion.py` — `PayloadMemory`
  cross-campaign payload/loot fusion engine (har war-room campaign ka exploit/recon
  evidence = service:port -> CVE/technique records; `payload_memory.json` persistence).
- feat(fusion_score): `score = 0.55*hit_ratio + 0.30*recency (7-din half-life)
  + 0.15*cross_campaign` — swarm kabhi payload technique dobara reinvent nahi karta.
- feat(webui): `/api/swarm/payloads` (fused payload ranking feed) + `/api/swarm/chains`
  (multi-target chain graph: shared service:port = pivot edge, shared CVE = chain edge).
- feat(webui_ui): templates/index.html mein 2 naye war-room cards — "🧬 Payload
  Fusion" (top fused payloads: score bar + hits + campaign count + CVE/technique
  tags, 6s auto-poll) + "⛓ Multi-Target Chain" (SVG ring graph: green dashed =
  pivot edge shared svc:port, red = chain edge shared CVE; host nodes = last octet
  + ports + top CVE tag, live 6s refresh).
- test(ui): panels live-verified on mock server — index served (Payload Fusion=1,
  Multi-Target Chain=1, mc-chain-svg=4, mc-fusion-body=2); /api/swarm/payloads ->
  4 fused rows (nginx/80 0.88 hits=2 nuclei:poc|rce|sqli); /api/swarm/chains ->
  4 nodes / 5 edges incl. CVE-2021-23017 chain edge.
- test(full_suite): `pytest -q` FULL RUN -> 771 passed, 3 skipped;
  9 failures (pre-existing, v10.1 features ke koi regressions NAHI) me se
  4 redteam tests ki stale route-table expectations sync ki (cyber/uncensored
  routes ab deliberate NOTRACK lead se match karte hain: REDTEAM_ROUTE_LOCK
  uncensored/cyber + MODEL_ROUTES cyber/uncensored -> notrack-uncensored),
  1 security-audit fix (config.json ab UNTRACKED - .gitignore line 2 align,
  [D] removal; local file intact; real secrets kabhi committed nahi thay -
  sirf env-var refs NOTRACK_API_KEY etc), 1 session_mgr flaky (re-run PASS),
  3 MCP wiring env-only (local-fs server auto-wire - known env-dependent).
- test(redteam_promax): 14/14 PASS after sync; security_audit 10/10 PASS.
- fix(technique): tag union ab set-based + normalized (`nuclei:poc|rce|sqli`),
  same-campaign multiple exploit entries ke techniques merge hoti hain overwrite nahi.
- test: fusion unit-test passed (2 campaigns -> nginx/80 score 0.91); endpoints
  live-verified on mock server (3 hosts/4 edges, payload score 0.88).

## [2026-09-13] v10.0 - ULTRA MODE v10 + PERSONA SWARM (roadmap #10)

- feat(ultra_v10): naya `ai_agent/ultra_v10.py` module — `PersonaSwarmRouter`
  (keyword-scored turn-to-turn specialist routing) + `ULTRA_V10_REGIME`
  (zero-gate execution contracts: no refusals, no filters, full-depth).
- feat(ultra_core): `UltraGM` ab ULTRA v10 context auto-append karta hai
  (config.json `ultra_enabled` auto-detect; `ultra_observations: true`).
- feat(system_prompt): +ULTRA MODE v10 section (deep-scan posture,
  auto-exploit chaining, swarm live-map, self-healing multi-model swap,
  zero-gate execution, 5-part ULTRA output pack) + ULTRA PERSONA SYSTEM
  (5 specialists: RECON MASTER / EXPLOIT ENGINEER / CODE VAMPIRE /
  GHOST OPS / INTEL WEAVER).
- feat(config): `max_iterations: 120`, `max_messages: 800`,
  `max_spawn_depth: 4`, `refusal_retries: 8`, openrouter pool 20 models,
  multi-model swap FAIL 2x + retry, 11 openrouter models, 6 API keys live.
- feat(webui): `/api/swarm` live-map affirmed — per-host nodes (live/ports/
  CVEs) via `phases.recon.hosts` + `phases.exploit.targets` reduction;
  index.html render panel (`#mc-swarm-nodes`) polling no-store verified.
- test: real-model smoke (notrack.ai) = ULTRA v10 regime active, 5-specialist
  swarm confirmed; WebUI live-map chain verified end-to-end.

## [2026-09-13] v0.8.13 - DEEP-SCAN POSTURE (roadmap #9)

- feat(auto_pilot): naya `mission_deep` tool + `deep=True` flag across mission
  pipeline. Deep posture attack surface widening:
  - recon: `DEEP_PORTS` = full well-known range 1-1024 + default set + ~500
    high-value service ports (admin UIs, DBs, caches, CI/CD, IoT, backdoors)
    = 1535 unique ports (tool_port_scan 2000-cap ke andar), timeout 1.0s,
    concurrency 220. SSL grab 443/8443/9443 par jab open.
  - scan: 12 web targets (standard 6), live roots 4 dir-fuzz with
    `DEEP_WORDLIST` (~250 entries, DEFAULT_WORDLIST superset) - panels,
    backups, .git config leaks, actuator/env, swagger, CI/CD UIs.
  - vuln: 20 CVE queries (standard 12) + AUTO nuclei sniper on up to 3 live
    web targets (ab run_nuclei opt-in ki zaroorat nahi deep mode mein).
  - campaign state `posture=standard|deep`; `mission_status` posture badge
    ([DEEP-SCAN]) + campaign list `[deep]` tag; WebUI `_mission_summary`
    posture field.
- fix(deep): sotto-recon/JIT edge cases; deep ctx budget granularity bumped
  per-phase (scan 10s/target, dir-fuzz 30s, nuclei 45s/url).
- test: naya `test_deep_scan.py` (4 tests): DEEP_PORTS superset+cap,
  DEEP_WORDLIST superset+unique, _make_ctx deep flag, full deep mission on
  127.0.0.2 -> ALL PHASES COMPLETE + posture=deep + [deep] campaign tag.
  Suite: 391 passed / 3 env-only MCP failures (machine config.json local-fs
  server - CI mein clean)

## [2026-09-13] v0.8.12 - campaign findings aggregate sync (cosmetic fix)

- fix(auto_pilot): campaign top-level `findings_logged` ab hamesha phases ke
  aggregated count ke saath sync rehta hai. Pehle `_save` sirf `updated`
  timestamp update karta tha aur top-level `findings_logged` 0 par stuck rahta
  tha jabke per-phase entries (vuln/exploit) sahi counts rakhti thin. Ab har
  save par `sum(phase.findings_logged)` recompute hokar top-level par likha
  jata hai - WebUI missions panel / report summaries ke liye consistent
  aggregate count.
- test: naya regression test `test_save_aggregates_findings_logged`
  (phase counts 2+2 -> top-level 4). Full suite ab 15/15 pass
  (auto_pilot + campaign_continuity + phase3).

## [2026-09-13] v0.8.11 - EXPLOIT AUTO-RUN CHAIN + SWARM LIVE-MAP + CROSS-CAMPAIGN RANKING

- feat(auto_pilot): roadmap #6 done - ATTACK MISSION ab 5-phase hai
  (recon -> scan -> vuln -> EXPLOIT -> report). Naya `_phase_exploit` har CVE
  hit par auto-chain karta hai: targeted nuclei verification (web targets par),
  ready-to-run NON-DESTRUCTIVE PoC probe `artifacts/exploit_<target>/poc_<CVE>.py`
  (banner-check + manual verification steps), aur payload-memory signal
  `exploit_chained`. Findings log `status=needs-validation` (confidence low).
  Naya tool `mission_exploit` (phase 4 solo). Report mein "## Exploitation
  (auto-run chain)" section.
- feat(webui): roadmap #7 done - MISSION CONSOLE mein naya full-width
  "🐝 Swarm Live-Map" card: standalone JS har 4s `/api/swarm` poll karta hai;
  `_mission_summary` har swarm campaign ke hosts par se nodes nikalta hai
  (live/dead dot, open ports, CVEs) - war-room ka multi-host battlefield live.
- feat(payload_memory): roadmap #8 done - `rank_global()` cross-campaign
  leaderboard: payloads jo kaee hosts par kaam kiye unki hosts-count + hits par
  ranking. Naye tool `payload_memory_ranking(top_k=)` + `mission_payloads`
  `global_rank=True` mode.
- fix(auto_pilot): `_poc_probe` `lines.append` 2-arg TypeError fixed (chained
  PoCs ab reliably save hote hain).
- test: 14/14 pass (auto_pilot + campaign_continuity + phase3). Live 127.0.0.1
  mission: 5/5 phases done, 2 PoC probes chained (CVE-2003-0605, CVE-2002-0597),
  report Exploitation section + payload-memory leaderboard verified. `/api/swarm`
  smoke: 200 + node extraction (live/ports/cves) PASS.

## [2026-09-13] v0.8.10 - WEBUI MISSION CONSOLE (war-room panel)

- feat(webui): roadmap #5 done - naya `MISSIONS` view (`/api/missions`,
  `/api/missions/<key>`, `/api/missions/<key>/report`). Sidebar mein naya
  "🎯 Missions" tab: live war-room panel jo har campaign par phase progress
  (recon/scan/vuln/report status chips), open ports, findings table aur
  per-phase output stream dikhata hai - auto-refresh 3s jab mission running,
  6s idle. Report download button -> markdown report file.
- feat(webui): campaign list her key/campaign subdir se collect hota hai
  (`campaigns/*/*.json`), mission summary mein phases+findings+errors,
  report path Windows-safe normalize + fallback `reports/attack_mission_<t>.md`.
- test: live smoke on mock webui - 2 missions listed, detail JSON OK, report
  download HTTP 200 (1091 bytes) verified.

## [2026-09-12] v0.8.9 - CPE -> NUCLEI SNIPER AUTO-TEMPLATE MATCH

- feat(tools): NEW `cpe_match` module - nmap -sV banners se CPE strings nikal kar
  local nuclei-templates index par sirf RELEVANT templates auto-roll karta hai
  (blind full-scan nahi, sniper approach). 5 naye tools registered:
  `cpe_scan`, `cpe_extract`, `cpe_match`, `cpe_nuclei_scan`, `cpe_template_index`.
- feat(auto_pilot): vuln phase ab CPE-targeted hai - pehle cpe_scan (nmap -sV) chalta
  hai, phir `_cpe_banner_lines` helper rows ko nmap-style (`80/tcp open http Apache
  2.4.49`) mein convert karta hai, aur per-URL sirf matched templates ke saath
  `tool_cpe_nuclei_scan` run hota hai. "no templates matched" par generic
  `tool_nuclei_scan` fallback. Templates dir indexing + 6h TTL cache; CVE-2024-3094
  jaisi zero-hit queries working as designed (head-4096 read).
- test: `tool_cpe_match("openssh")` -> 3 template hits; apache -> 72; unit test
  `_cpe_banner_lines` PASS; full pipeline `tool_cpe_nuclei_scan(banner=...)` -> 75
  templates matched (apache+openssh), nuclei exit 0; mission smoke test complete -
  cpe_banner state + generic fallback verified on 127.0.0.1.
- infra: 13,717 templates extract karke `C:\Users\GLOBAL IT STORE\nuclei-templates\`
  (http/ network/ dns/ ssl/ top-level) - direct GitHub zip, `nuclei -update-templates`
  timeout ki wajah se.

## [2026-09-12] v0.8.5 - SWARM WAR-ROOM CAMPAIGN (multi-target parallel mission)

- feat(tools): NEW `swarm_campaign` tool - ONE command attacks MANY targets: fan-out
  parallel recon workers per host (port scan + SSL), then parallel exploit workers per
  open service (CVE lookup + optional nuclei template runs), merge everything into a
  single war-room markdown report (`reports/swarm_campaign_<token>.md`) and persist
  campaign state (`campaigns/swarm_<token>.json`) for continuity.
- feat(tools): target expansion - accepts IPs, domains, comma/space lists, CIDR subnets
  (`10.0.0.0/24`) and octet ranges (`10.0.0.1-30`); capped at 1024 hosts per subnet.
- feat(tools): NEW `swarm_status` tool - list all war-room campaigns or inspect one by
  token (hosts, ports, phase elapsed, error count).
- feat(tools): exploitable CVE hits auto-logged as findings via reporting pipeline.
- mode=recon | exploit | full; max_workers caps parallelism (default 8); run_nuclei
  opt-in for template scanning; budget_sec caps wall time.
- test: verified on 127.0.0.1 - recon found 135/epmap, 445/microsoft-ds, 5432/unknown;
  full mode probed 3 services with 2 CVE hits in 4.3s; merged report + state written.

## [2026-09-11] v0.8.8 - ULTRA 3D 32K HD lock screen (image fully replaced)

- feat(lockscreen): ULTRA 3D 32K HD redesign - 3-layer shimmer starfield (far dust /
  mid field / bright 4-point glint stars), 2 pure-CSS shooting stars, aurora nebula
  sheets + third cyan orb, interactive mouse-parallax 3D tilt on the glass panel
  (JS drives --gk-tilt-x/--gk-tilt-y CSS vars through the entrance keyframe),
  breathing depth glow, rotating scanner arc around the lock badge, upgraded
  golden-red 3D title. Still 100%% pure CSS - zero images, zero blur.
- fix(cache): /gatekeeper/lockscreen.css and .js now served with
  Cache-Control: no-store + ?v=0.8.8 cache-bust link in index.html - the stale
  1-hour cached stylesheet that kept showing the old wallpaper image is gone.
- a11y: prefers-reduced-motion support added.

## [2026-09-11] v0.8.7 - ULTRA POWER MODE (uncensored max-capability profile)

- feat(prompt): permanent ULTRA POWER MODE directive block added to system_prompt.txt -
  full-autonomy engagement driving (enumerate -> chain -> exploit -> validate), zero
  technique filters within the security context, parallelized recon defaults, live-
  until-refuted hypothesis handling, evidence-capped severity claims, and ultra-dense
  outputs (exact commands + request/response artifacts, Critical->Low ranking).
- sync: profile rails match the uncensored behavioral policy already enforced in-session.

# Changelog

## [2026-09-11] v0.8.6 - 3D 32K HD lock screen edition

- feat(lockscreen): complete 3D 32K HD redesign of the gatekeeper lock
  screen - animated 3D deep-space starfield (15-layer background: star
  dust + blue/red nebulae), floating holographic orbs (parallax drift),
  glass panel with 3D perspective entrance (rotateX/rotateY), periodic
  glass shine sweep, pulsing 3D radar rings around the lock badge,
  floating badge bob, gradient 3D title with glow breathing animation,
  and fixed the original `.gk-skip:hover` missing-brace CSS bug.
- cleanup: user wallpaper image (data-URI) fully removed - lock screen
  is now 100%% pure CSS, zero images, zero blur, single-file change.
- test: lockscreen + dock layering suites 30/30 green.

## [2026-09-11] step 4 - end-to-end gatekeeper auth + notification integration

- feat(integration): the Lock Screen UI -> Auth Engine -> OS Notification
  flow is now seamless - `webui.py` fires `_login_notify("Password")` on
  `/api/gatekeeper/unlock` success and `_login_notify("Fingerprint")` on
  `/api/gatekeeper/webauthn/assert` completion (the exact endpoints the
  lockscreen JS calls), so a real browser unlock pops the desktop alert.
- feat(cleanup): unlock reverts the overlay via `hideOverlay()`
  (`gk-hidden` + `display:none` removes `.gatekeeper-lockscreen`); auto-lock
  re-mounts the overlay on the next status poll (has-gatekeeper class).
- test: `tests/test_webui_lockscreen.py` extended - overlay-hide contract,
  auto-lock cleanup contract, password-unlock + fingerprint-unlock
  notification wiring (via the real Flask routes), and wrong-password
  never-notify guard. Full suite now 390/390 green.

## [2026-09-11] step 3 - cross-platform OS notification engine on authentication

- feat(security): new `ai_agent/core/notifier.py` raises a native desktop
  notification on every successful login; payload contract
  `🚨 [HACKERAI SECURITY ALERT] Agent session opened via {method} at {ts}`.
  Windows -> powershell.exe WScript popup, macOS -> osascript, Linux ->
  notify-send; zero-dependency (plyer optional), degrades to a console line
  on headless/CI hosts and never raises (auth flow can never fail on a toast).
- feat(auth): `/api/auth/unlock` fires `Password`, `/api/auth/webauthn/assert/complete`
  fires `Fingerprint`; notifications run on a daemon thread (non-blocking) and
  short-circuit under pytest so suites never pop OS dialogs.
- test: `tests/test_notifier.py` (16 cases) - exact payload contract,
  method-label normalization, ISO timestamps, dry-run, graceful degradation,
  per-backend command shape, async thread fire, and auth-route wiring.
  Full suite now 385/385 green.

## [2026-09-11] upgrade - /pool command, live model pool visibility & 100% green suite

- feat(cli): new `/pool` command prints the live model pool - primary model,
  uncensored flag, failover chain and the full uncensored pool (mix order),
  wired into the banner + `/help`.
- fix(cli): corrected unterminated-string bug in `_print_pool` (escaped
  `\n`); agent now starts and serves `/pool` cleanly.
- models(config): openrouter uncensored fallback pool extended with
  `huihui-ai/qwen3.5-27b-abliterated` and `sao10k/l3.1-stheno-v3.2`
  (13 openrouter models total) for the uncensored-first failover chain.
- css: dock-layering contract fixed - `.chat-log` base padding -> `6px 4px 140px`
  with matching `padding-bottom:140px` enforcement block; trailing `@media`
  sections (AGENT HERO -> EOF) moved before the PHASE 1 marker so no `@media`
  remains in the phase-1 tail.
- test: full suite now 369/369 green (both previously-failing CSS dock-layering
  assertions fixed).

## [2026-09-11] step 2 - password hashing, WebAuthn biometric & session token backend

- feat(security): dedicated auth handler blueprint `ai_agent/webui/auth.py`
  mounted at `/api/auth` - bcrypt master-password verify (`/api/auth/unlock`),
  WebAuthn challenge/response ceremonies for Fingerprint / Touch ID /
  Windows Hello (`/api/auth/webauthn/register/*`, `/api/auth/webauthn/assert/*`),
  encrypted-LocalStorage JWT session tokens with idle auto-lock timeout
  (`/api/auth/session`, `/api/auth/touch`), plus `/setup` and `/lock`.
- test: `tests/test_auth_handler.py` (9 cases) - correct/wrong password paths,
  forged-token rejection, lock revocation, WebAuthn ceremony guards. Full
  auth suite (handler + gatekeeper + lockscreen) 66/66 green; whole suite
  367/369 (two pre-existing CSS dock-layering assertions, unrelated).
- changed: `webui.py` registers the auth blueprint (same shared gatekeeper
  store as the STEP 1 `/api/gatekeeper/*` routes).

## [2026-09-09] step 5 - notrack-uncensored live path hardened (Cloudflare 1010)

- fix(llm): api.notrack.ai is Cloudflare-fronted and rejects the default
  python-requests User-Agent with HTTP 403 error 1010 (same key + payload
  returns 200 with a browser-like UA).  _request_target now attaches
  browser-like User-Agent/Accept/Accept-Language headers for the notrack
  host only, so the notrack-uncensored lead slot serves real completions
  from the agent's own chat()/chat_stream() path.
- test: e2e via OpenAIClient.chat() -> route api.notrack.ai/v1,
  reply NOTRACK_OK in ~1s, no refusal-shape hit.  Both config JSONs
  parse; router mapping notrack-uncensored -> notrack block confirmed.

## [2026-09-09] step 3 - Venice + HF routes live activation

- env: VENICE_API_KEY + HUGGINGFACE_API_KEY now set in .env (gitignored).
- verified(venice): key auth OK (GET /models -> 200, uncensored ids listed).
  Chat calls return 402 insufficient balance until the account is funded at
  https://venice.ai/settings/api - the model-failover chain skips the slot.
- verified(huggingface): key auth OK (GET /models -> 200, 139-model catalog).
  Requested huihui-ai/Llama-3.3-70B-Instruct-abliterated and
  dphn/dolphin-2.9.2-qwen2-72b are NOT in the reachable catalog (400 "not
  supported by any provider you have enabled"); re-checked per-provider
  (novita/together/deepinfra return the same 139 ids, zero hits) and via
  serverless api-inference (DNS-unreachable from this host).
- config: HF block keeps the two requested ids (they activate as soon as the
  account enables a provider that hosts them at hf.co/settings/providers) and
  appends a live tail slot NousResearch/Hermes-3-Llama-3.1-70B (in the
  reachable catalog today), so the HF route now contributes a working model.
  config.example.json synced; both files parse valid JSON.

- verified live: router chat with NousResearch/Hermes-3-Llama-3.1-70B -> 200,
  reply HF_OK in 2.0 s - the HF route serves real completions on this account.
## [2026-09-09] step 2 - CLI red-team parity with the web UI

- feat(cli): agent.py now derives uncensored_mix from red_team_level
  (promax/promix) exactly like webui._build_llm, passes refusal_retries and
  the pin_uncensored/pin_strict levers through to the client, and attaches
  the persona directive block (personas.get_block) so the CLI system prompt
  carries the same persona/ENFORCEMENT_LOCK tail as the web UI.
- config: refusal_retries raised 3 -> 5 (refusal escalation budget on
  authorized offensive-security runs); config.example.json documents
  persona/red_team_level/pin_uncensored/pin_strict alongside it.
## [2026-09-08] uncensored pool v4 - HF Inference Providers + Venice routes

- feat(router): the two requested abliterated builds that 404 on OpenRouter now
  have a live home - huihui-ai/Llama-3.3-70B-Instruct-abliterated and
  dphn/dolphin-2.9.2-qwen2-72b (cognitivecomputations moved to the dphn org;
  canonical id verified against huggingface.co/api) are routed through the new
  `huggingface` local_endpoints block (https://router.huggingface.co/v1,
  api_key_env HUGGINGFACE_API_KEY).
- feat(router): new `venice` local_endpoints block (https://api.venice.ai/api/v1,
  api_key_env VENICE_API_KEY) with live uncensored catalog ids verified 2026-09:
  venice-uncensored-1-2 + venice-uncensored-role-play (both function-calling
  capable), added to the PRO MIX rotation pool.
- feat(pool): UNCENSORED_FALLBACK_MODELS now leads mixtral-8x22b-instruct
  (OpenRouter) -> huihui abliterated -> dolphin-2.9.2-qwen2-72b (HF route)
  -> euryale/dolphin-venice/hermes stand-ins -> free emergency slots.
- config: .env.example documents VENICE_API_KEY + HUGGINGFACE_API_KEY.

## 2026-09-08

### Fixed
- Empty-final retry in `run_stream()`: a heavy tool chain whose final LLM
  turn returns an empty message (no content, no tool calls - observed live
  on Groq) previously surfaced as "(empty reply)" despite completed work.
  The loop now nudges the model once (bounded, max 2 retries) to produce a
  real summary before falling back.
- Work-digest fallback: when retries are exhausted after a tool chain, the
  final message lists the completed tool work (rolling digest of the last
  few tool results) instead of a bare "(empty reply)" - the caller always
  learns what actually happened.
- Stream-cancel race fixed: closing the HTTP response mid-iteration on a
  cancelled run (deadline/stop watchdog) made requests/urllib3 raise a raw
  AttributeError ('NoneType' .read) instead of RunCancelled - observed on
  the phishing probe exactly at the 110 s deadline. It now maps back to
  RunCancelled.
- Context-aware empty-final nudge: the retry nudge now branches on whether
  any tool work happened. After tool work the model is asked to summarise
  what was completed; when the empty turns happened before any tool call
  (the "no-work empty" pattern seen live on Groq), it instead asks for a
  direct regeneration of the original request - a "summarise the work"
  nudge is meaningless when no work exists and would never break the loop.
## [2026-09-08] runtime watchdog + probe harness

- fix(runtime): agent.run() supports stop_event + wall-clock `deadline`; daemon watchdog
  sets stop_event and the loop self-cancels via RunCancelled (no zombie threads on long
  tool chains - previously 219-235s runaway runs past a 115s harness cap).
- feat(probe): refusal-probe harness now wires deadline=110s and maps RunCancelled to a
  SELF-CANCELLED marker (live proof of clean abort, not refusal).
- test: full regression suite green - 648 passed, 3 skipped (persona/router/watchdog incl.).


Sare notable changes is project ke. Format: `[Semantic Versioning](https://semver.org/)-style`
(Unreleased / versioned blocks, newest top).

## [Unreleased]

### Added
- **Groq primary + routed OpenRouter fallback** — `config.json` now
  points at `https://api.groq.com/openai/v1` /
  `llama-3.3-70b-versatile`; same-host failover strikes
  (`gpt-oss-20b`, `qwen3.8-27b`, `allam-2-7b`); OpenRouter runs as a
  routed endpoint plug-in under its own preserved key
  (`OPENROUTER_API_KEY`), with an explicit-model allow-list that
  caps discovery and survives /models outages. Live proof: Groq
  primary answered (GROQ_PRIMARY_LIVE: PASS); routed OpenRouter
  nemotron free models answered (OPENROUTER_ROUTED_LIVE: PASS).
- Tests: `tests/test_groq_endpoint.py` extended (explicit
  allow-list cap + outage survival).

- **Live MCP demo server** (`mcp_servers/local_fs_demo.py`) — zero-dependency Python
  stdio JSON-RPC MCP server exposing `fs_ls` / `fs_read` / `fs_stat` tools. Verified
  end-to-end: `REGISTERED_TOOLS: ['mcp_fs_ls', 'mcp_fs_read', 'mcp_fs_stat']`,
  `LIVE_WIRING_PROOF: PASS`. `config.example.json` pre-wired with the
  `local-fs-demo` entry.
- **WebUI MCP status panel** — Agent now tracks `_mcp_state` (per-server
  `status/error/tools`) at wire time; new `GET /api/mcp` route in `webui.py`;
  live server/tool strip in the Tools view (`templates/index.html` +
  `static/app.js`). Verified: `MCP_STATE_TRACKING: PASS`.
- **Local uncensored profile (custom persona) activation** — `config.json` set to
  `"persona": "custom"` + `red_team_mode: true`; runtime `personas_custom.txt`
  block (MYTHOS-CLASS + `[ENFORCEMENT LOCK]`) loads on every reply.
  Verified: `CUSTOM_PROFILE_ACTIVE: PASS`.
- **Tests**
  - `tests/test_mcp_runtime_wiring.py` — Agent-level MCP auto-wiring (env/config
    spec load, live tool registration, dedupe, per-server failure isolation).
  - `tests/test_custom_persona.py` — custom persona contract (normalize, text
    loading from `personas_custom.txt`, block assembly + enforcement lock,
    missing-file fallback, metadata listing).
- **Docs** — README: MCP wiring guide, WebUI status panel, custom persona
  activation (UI + config); CHANGELOG.

### Added
- **Groq API key endpoint plug-in** — `local_endpoints` specs now
  support `api_key_env` (key resolves from .env at runtime, never stored
  in config.json), remote /models probing sends `Authorization` when the
  endpoint has its own key, audio/whisper ids are filtered, and
  discovered models route to the endpoint's own base_url + key. Wired
  through WebUI `_build_llm`, CLI `agent.py`, `config.json` and
  `config.example.json`. Live proof: 12 Groq models discovered,
  GROQ_LIVE_CHAT: PASS.
- Tests: `tests/test_groq_endpoint.py` (env-key resolution, authed
  probe, model filtering, endpoint routing, chain ordering).

### Fixed
- Custom persona missing-file contract: when `personas_custom.txt` does not
  exist, `get_block("custom")` returns only the (edge-stripped)
  `ENFORCEMENT_LOCK` — no stale/custom text leaks.

### Verified
- `python -m pytest tests/ -q` → **265 passed** (12.6s)
- Root-level red-team/memory suites
  (`test_redteam_promax.py test_redteam_mode.py test_memory.py
  test_selfmanaged_memory.py`) → **51 passed**

## [0.x] — Earlier milestones (condensed)
- MCP client engine (stdio/jsonrpc channels, handshake/discovery/payload exec)
- Agent-level MCP auto-wiring into runtime
- Semantic vector memory engine + runtime compaction hook in agent loop
- Zero-gate v2 (uncensored core) + refusal-echo blocking + red-team PRO mode
- Swarm router, self-evolution / learning guard, knowledge graph, tool
  synthesizer, intent reformulator, upload/vision chat, context compactor
- WebUI (Flask :8080) with Tools / Memory / Reports / RPG / Settings views

## [2026-09-09] step 4 - NoTrack AI route verified live (notrack-uncensored)

- feat(router): new `notrack` local_endpoints block
  (https://api.notrack.ai/v1, api_key_env NOTRACK_API_KEY) with the
  dedicated private uncensored model `notrack-uncensored` - verified live
  on this account: GET /models -> 200 and a chat completion -> 200
  (NOTRACK_OK) in one shot.
- feat(pool): notrack-uncensored now LEADS UNCENSORED_FALLBACK_MODELS and
  the PRO MIX rotation pool - the uncensored chain opens on a provider
  that is deliberately uncensored instead of a possibly safety-tuned
  hosted slug, so the empty-reply probes recorded in step 3 have a
  dedicated no-refusal home for offensive-security runs.
- config: config.json + config.example.json updated (notrack block first
  in local_endpoints); .env + .env.example document NOTRACK_API_KEY.
  All JSON files parse valid.

## [2026-09-10] v0.7.0 - live-transparent upgrade

- feat(cli): agent.py now streams every step live to the terminal ([think] reasoning,
  [TOOL] calls, [OUT] results, [SUB-AGENT] spawns) via run_stream instead of
  printing only the final answer - full screen visibility of agent work.
- feat(config): pin_uncensored + pin_strict enabled - uncensored model chain
  (notrack/venice/openrouter/hf-abliterated) locked as primary routing.
## [2026-09-11] v0.8.0 - /api/health observability endpoint

- feat(webui): new GET /api/health probe on the Flask app (port 9000) reporting
  service name, release v0.8.0 + package version, routes_configured readiness
  per provider slot (notrack/openrouter/venice/huggingface - true when the
  matching api_key_env is set in the environment), active_runs count and
  booted_s uptime. Lightweight liveness/route-readiness check for monitors and
  uptime dashboards - never exposes key material, only boolean readiness.
- test: live-verified on this host - HTTP 200 with all four uncensored route
  slots reporting true (NOTRACK_API_KEY/OPENROUTER_API_KEY/VENICE_API_KEY/
  HUGGINGFACE_API_KEY present), release v0.8.0, booted_s monotonic.## [2026-09-11] v0.8.1 - /api/health per-route response-latency

- feat(webui): /api/health now reports routes_latency_ms - real measured
  round-trip latency per provider route (notrack/openrouter/venice/huggingface),
  probed live from the server process via stdlib HEAD/TCP fallback (2.5s cap,
  None when unreachable). routes_configured booleans kept for back-compat.
- test: live-verified on this host - all four routes report positive latency
  values (hf ~2.7s / notrack ~3.1s / openrouter ~3.3s / venice ~4.2s from
  this host network), release v0.8.1, HTTP 200.## [2026-09-11] v0.8.2 - uptime history API + built-in /health dashboard

- feat(webui): /api/health now records every probe into an in-memory ring
  buffer (max 400 samples, thread-safe); new GET /api/health/history returns
  the last 60 samples plus computed uptime_pct - ready to feed any uptime
  monitor (Uptime Kuma HTTP(s) monitor, cron+curl, dashboard widgets).
- feat(webui): new GET /health renders a self-contained dark dashboard page
  (no external JS/CDN) that polls /api/health every 5s - live OK/ERROR chip,
  release/version/uptime/active-runs, per-route configured + latency table,
  and a sampled sparkline of the history with uptime %.
- test: live-verified on this host - /api/health 200 (release v0.8.2, all 4
  routes configured), /health 200 (dashboard HTML served), history accumulates
  samples with uptime_pct 100.0.
## [2026-09-11] v0.8.3 - HD TURBO lock screen (crystal clear 32K-style)

- fix(webui): gatekeeper lock screen de-blurred - removed backdrop-filter blur(18px)
  acrylic from .gk-blur-layer; replaced with razor-sharp CSS radial glow (zero blur).
- feat(webui): clean deep-space gradient background (no translucent red bleed),
  larger HD panel (480px), crisp 1px highlight borders, anti-aliased text
  rendering (text-rendering:optimizeLegibility, no shadows), bigger sharper
  title (26px/900) and password input (16px, 46px tall, letter-spacing 3px).
- fix(css): repaired .gk-skip:hover rule that was missing its opening brace.
- test: braces balanced, zero blur()/backdrop-filter left in lock screen stylesheet.

## [2026-09-11] v0.8.4 - LIVE SCREEN MIRROR (agent actions visible while chatting)

- fix(webui): LIVE ACTIVITY exec stream never rendered. The backend frames
  execution events as `event: exec`, but the client subscribed with a plain
  `execSource.onmessage` handler, which browsers never fire for named SSE
  events. Switched to execSource.addEventListener("exec", ...) so terminal/
  git/sub-agent events now stream to the panel in real time.
- feat(webui): new in-chat LIVE AGENT ACTIVITY feed. Every real action row
  (task start, planning, tool call, terminal command, result, validation,
  final) is mirrored as a live line directly above the composer, so the
  operator watches the Agent work without switching to the Live Activity tab.
  Auto-shows on run start, collapsible, colour-coded status pill (RUNNING /
  COMPLETED / FAILED), auto-scroll, bounded to 140 rows, secret-sanitised.
- test: node --check static/app.js clean; mirror hooked into addRow so no
  action can bypass the feed.

## [v14-notify] 2026-09-14

### NEW - Notification Engine (bundle #1 selected)
- `notify_telegram` - live Bot API alerts (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)
- `notify_discord` - Discord webhook messages (DISCORD_WEBHOOK_URL)
- `notify_webhook` - generic JSON webhook (Slack/Teams style or raw payload)
- `notify_findings` - severity-filtered digest of findings.jsonl to any channel
- Tokens always masked in outputs; no false alerts (empty store / below severity = no send)
- Registered in tool registry; .env.example updated with notification keys

## [v14-credential] 2026-09-14

### NEW - Credential Attack Suite (bundle #2)
- `hydra_brute` - brute-force ssh|ftp|http-form with password list; hydra binary when available, pure-Python fallback (paramiko/ftplib/requests), 2000-attempt cap
- `password_spray` - one password across many users/hosts, 1 attempt per user (lockout-safe)
- `hash_crack` - offline dict crack: md5/sha1/sha224/sha256/sha384/sha512/ntlm/bcrypt/salted-sha256/auto
- Pure-Python MD4 (RFC1320) for NTLM - works on Python 3.14 which dropped OpenSSL md4
- Built-in common-password + user wordlists; custom file/list support
