# Reconnaissance & Attack Surface Mapping

Systematic recon = the difference between a random scan and a complete attack-surface map.
Follow the order below; each stage's output feeds the next. Never jump to exploitation
before the surface is mapped.

## Phase A — Scope & Rules of Engagement

1. Call `set_scope(targets)` FIRST with every host/domain the user declared in scope.
2. Before scanning any host, call `check_scope(host)` — never touch out-of-scope assets.
3. Record the engagement's boundaries (IPs, CIDRs, domains, excluded assets).

## Phase B — Passive Recon (no direct contact with target)

Goal: build an asset inventory without sending a single packet.

- DNS: `dns_lookup` (A, AAAA, CNAME, MX, NS, TXT) on root domain and each subdomain.
  TXT records leak SPF/DMARC, verification tokens, and sometimes secrets.
- Subdomains: `subdomain_enum` (certificate transparency / crt.sh + common names).
  Also check the TLS certificate SANs from `ssl_info` — certs list every hostname.
- WHOIS / RDAP: `whois` for registrar, org, creation date, and abuse contacts.
- Check for exposed tech footprint: web search for `site:target.com` leaks, GitHub
  code search for the domain (repo names, config files), paste/dump sites.
- Cloud/asset discovery: enumerate bucket names (`target`, `target-backup`, `target-dev`),
  and look for public code repositories mentioning the org.

## Phase C — Active Service Enumeration

Goal: find every reachable service and its version.

1. Port scan the FULL scope, not just the web ports:
   - Broad TCP: `port_scan` with the default port list first (fast), then widen.
   - If nmap is installed: `nmap_scan` with `-sV -Pn --top-ports 1000` for versions.
   - Re-scan ANY open port with service detection + `-p-` only when evidence justifies it.
2. For every open WEB port (80, 443, 8000, 8080, 8443, 3000, 8888, 9000):
   - `http_request` for the root page and `check_headers` (Server, X-Powered-By,
     X-AspNet-Version, Via, Set-Cookie flags, HSTS, CSP).
   - `tech_detect` to fingerprint CMS/framework/version.
   - `robots_txt` + `extract_links` for more surface.
3. For non-web ports, note the service banner and match to known attack classes:
   21 FTP, 22 SSH, 25 SMTP, 53 DNS, 139/445 SMB, 1433 MSSQL, 1521 Oracle, 2049 NFS,
   2375 Docker, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 6379 Redis, 9200 Elasticsearch,
   11211 Memcached, 27017 MongoDB.

## Phase D — Directory & Endpoint Fuzzing

- `dir_fuzz` / `gobuster_dir` / `ffuf_fuzz` on each web root with a wordlist sized to
  the time budget (start small, expand if nothing interesting appears).
- Look for: `/admin`, `/api`, `/backup`, `/uploads`, `/swagger`, `/graphql`,
  `.git/`, `.env`, `/.well-known/`, `server-status`, config files, and API docs.
- Follow up every found path with `http_request` and classify it (auth-gated? verbose?
  dynamic parameters?).

## Phase E — Consolidation

- Merge findings into the working map: hosts → ports → services → versions → paths → params.
- For every software + version identified, queue `cve_lookup` in the vulnerability-mapping phase.
- Empty result on a scan = a signal, not an answer. Reconsider: wrong target? wrong port?
  WAF/firewall filtering? Try an alternative (different wordlist, `-Pn`, UDP, wider range).

## Anti-patterns

- Scanning out of scope or forgetting `check_scope` before each new host.
- Dumping raw scan output into the conversation — distill into a map.
- Fuzzing deep paths before the root surface is mapped.
- Ignoring non-web services (the database on 3306 may be more valuable than the app).
