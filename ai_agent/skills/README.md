# Skill Library (On-Demand Methodology)

Curated, on-demand pentest methodology guides. Skills are **not** loaded into the
agent's context by default — the agent queries the library with `search_skills(query)`
and loads only what a task needs via `load_skill(skill_id)` (max 1-5 skills per task
context). This keeps the static system prompt lean and the reasoning context focused.

## How it works

- `search_skills(query)` — keyword/alias search over every skill's metadata
  (id, title, description, tags, keywords) + a content preview. Returns ranked
  matches with relevance scores.
- `load_skill(skill_id)` — loads one skill's `guide.md` (+ metadata header) into
  the reasoning context, truncated to a safe size.

## Available skills

| id | title | category | tags |
|---|---|---|---|
| `recon_methodology` | Reconnaissance & Attack Surface Mapping | methodology | recon, osint, enumeration, discovery |
| `web_exploitation_patterns` | Web Application Exploitation Patterns | methodology | sqli, xss, ssrf, xxe, ssti, idor, jwt |
| `active_directory` | Active Directory Attack & Defense Playbook | methodology | kerberos, kerberoast, llmnr, pth, ad |
| `report_templates` | Pentest Report Templates & Writing Standards | reporting | cvss, cwe, writeup, template |

## Adding a new skill

1. Create a folder under `ai_agent/skills/<skill_id>/` (lowercase, underscores).
2. Add `skill.json` with: `id`, `title`, `version`, `category`, `description`,
   `tags`, `keywords` (aliases for search), `phases`, `tools`, `load_budget`,
   `when_to_use`.
3. Add `guide.md` with the methodology — structured markdown, checklists over prose.
4. No registry changes needed: `search_skills` discovers the library dynamically.

## Rules

- Skills provide methodology/approach **only** — they never grant tools,
  permissions, or authorization.
- Load at most **1-5** skills per task context; unload (drop from context) when
  the phase they serve is done.
- When spawning a sub-agent, relevant skills can be included in its task context
  (max 5) so it runs systematically without a bloated global prompt.
