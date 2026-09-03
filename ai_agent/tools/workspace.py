"""Workspace repository mapping & large-context indexing tools.

Builds and caches a whole-workspace model the agent can query across chat
turns instead of relying on single-file context windows:

  workspace_scan     -> file tree + per-file stats (language, size, lines)
  workspace_symbols  -> function/class signatures per file (with lines)
  workspace_deps     -> import/dependency graph (who imports what, and the
                        reverse: who depends on a file)
  workspace_query    -> cross-reference lookup: where a symbol is defined,
                        which files import a module, what a file depends on

The WorkspaceIndex instance is owned by the Agent (one per conversation) so
the map survives across turns: scanning is mtime-cached, re-parsing only
files that actually changed on disk.
"""

import fnmatch
import os
import re
import threading
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", ".nox", "dist", "build", ".next", ".nuxt", "target",
    "vendor", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    "htmlcov", ".idea", ".vscode", ".vs", "bower_components", "jspm_packages",
    ".cache", "tmp", "temp", ".gradle", ".sass-cache", ".parcel-cache",
})
_IGNORE_FILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Gemfile.lock", "Cargo.lock", "composer.lock",
})

_EXT_LANG = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".cs": "csharp", ".rb": "ruby",
    ".php": "php", ".swift": "swift", ".sh": "shell", ".bash": "shell",
    ".zsh": "shell", ".ps1": "powershell", ".sql": "sql",
    ".html": "html", ".htm": "html", ".css": "css", ".scss": "scss",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".xml": "xml",
    ".md": "markdown", ".rst": "markdown", ".txt": "text",
    ".csv": "data", ".tsv": "data", ".log": "log", ".env": "env",
}

_SOURCE_EXTS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".h",
    ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".rb", ".php", ".swift",
    ".sh", ".bash", ".kt", ".sql", ".html", ".css", ".scss",
})

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def lang_of(path):
    """Best-guess programming language for a file path (by extension)."""
    name = os.path.basename(path).lower()
    if name in ("dockerfile", "containerfile"):
        return "dockerfile"
    if name in ("makefile",):
        return "makefile"
    if name in ("cmakelists.txt",):
        return "cmake"
    if name.startswith(".") and name.endswith("rc"):
        return "config"
    return _EXT_LANG.get(os.path.splitext(name)[1], "unknown")


def _is_ignored_dir(name):
    return name in _IGNORE_DIRS or name.startswith(".")


# ---------------------------------------------------------------------------
# Symbol extraction (regex-based, stdlib only)
# ---------------------------------------------------------------------------

_SYMBOL_PATTERNS = {
    # (pattern, kind) applied per line, first match wins per line
    "python": [
        (re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),
         "function"),
        (re.compile(r"^\s*class\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?\s*:"),
         "class"),
    ],
    "javascript": [
        (re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?function\s*([A-Za-z_$]\w*)\s*"
            r"\(([^)]*)\)"), "function"),
        (re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*"
            r"(?:async\s*)?(?:\(([^)]*)\)\s*=>|([A-Za-z_$]\w*)\s*=>)"),
         "function"),
        (re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$]\w*)\s*(?:extends"
                    r"\s+[A-Za-z_$]\w*)?\s*\{"), "class"),
    ],
    "typescript": [
        (re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?function\s*([A-Za-z_$]\w*)\s*"
            r"\(([^)]*)\)"), "function"),
        (re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)\s*:\s*"
            r"(?:[A-Za-z_$][\w<>\[\], ]*)?\s*=\s*(?:async\s*)?(?:\(([^)]*)\)"
            r"\s*=>|([A-Za-z_$]\w*)\s*=>)"), "function"),
        (re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+"
                    r"([A-Za-z_$]\w*)"), "class"),
        (re.compile(r"^\s*(?:export\s+)?(?:interface|type|enum)\s+"
                    r"([A-Za-z_$]\w*)"), "type"),
    ],
    "go": [
        (re.compile(r"^\s*func\s+(?:\([^)]*\)\s+)?([A-Za-z_]\w*)\s*"
                    r"\(([^)]*)\)"), "function"),
        (re.compile(r"^\s*type\s+([A-Za-z_]\w*)\s+(?:struct|interface)\s*\{"),
         "type"),
    ],
    "rust": [
        (re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*"
                    r"\(([^)]*)\)"), "function"),
        (re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait|impl)\s+"
                    r"([A-Za-z_]\w*)"), "type"),
    ],
    "java": [
        (re.compile(r"^\s*(?:public|private|protected|static|final|abstract|"
                    r"synchronized|native|default|strictfp\s+)*"
                    r"(?:[\w<>\[\], .]+?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
                    r"(?:throws\s+[\w, ]+)?\s*\{"), "function"),
        (re.compile(r"^\s*(?:public|final|abstract)?\s*(?:class|interface|"
                    r"enum|record|@interface)\s+([A-Za-z_]\w*)"), "class"),
    ],
    "cpp": [
        (re.compile(r"^\s*(?:virtual\s+|inline\s+|static\s+|const\s+|"
                    r"explicit\s+|friend\s+)*(?:[\w:<>\[\], *&]+?)\s+"
                    r"([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:const\s*)?\{"),
         "function"),
        (re.compile(r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)"), "class"),
    ],
    "c": [
        (re.compile(r"^\s*(?:static\s+|inline\s+|const\s+)*[\w *&]+?\s+"
                    r"([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{"), "function"),
    ],
    "csharp": [
        (re.compile(r"^\s*(?:public|private|protected|internal|static|"
                    r"virtual|override|abstract|async|sealed|readonly|"
                    r"partial\s+)*[\w<>\[\], ?]+?\s+([A-Za-z_]\w*)\s*"
                    r"\(([^)]*)\)\s*(?:=>|\{)"), "function"),
        (re.compile(r"^\s*(?:public|internal|abstract|sealed|static\s+)*"
                    r"(?:class|interface|record|struct|enum)\s+"
                    r"([A-Za-z_]\w*)"), "class"),
    ],
    "ruby": [
        (re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?"),
         "function"),
        (re.compile(r"^\s*class\s+([A-Za-z_:]\w*)"), "class"),
    ],
    "php": [
        (re.compile(r"^\s*(?:public|private|protected|static|abstract|final|"
                    r"function)\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),
         "function"),
        (re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_]\w*)"),
         "class"),
    ],
    "kotlin": [
        (re.compile(r"^\s*(?:fun|suspend fun)\s+([A-Za-z_]\w*)\s*"
                    r"\(([^)]*)\)"), "function"),
        (re.compile(r"^\s*(?:class|interface|object|enum class|data class|"
                    r"sealed class)\s+([A-Za-z_]\w*)"), "class"),
    ],
    "swift": [
        (re.compile(r"^\s*(?:public|private|internal|fileprivate|static|"
                    r"class|func)\s+func\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),
         "function"),
        (re.compile(r"^\s*(?:public|private|internal|final|open\s+)*"
                    r"(?:class|struct|enum|protocol)\s+([A-Za-z_]\w*)"),
         "class"),
    ],
    "shell": [
        (re.compile(r"^\s*([A-Za-z_]\w*)\s*\(\s*\)\s*\{"), "function"),
    ],
}

# Cache for compiled patterns of dynamic languages (kept simple: static table
# above is enough; this is a marker for future extension).


def extract_symbols(text, language, path=""):
    """Return [(kind, name, signature, line_no), ...] for one source file."""
    pats = _SYMBOL_PATTERNS.get(language, [])
    if not pats:
        return []
    out = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        for rx, kind in pats:
            m = rx.match(line)
            if m:
                name = m.group(1)
                args = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                args = " ".join((args or "").split())[:200]
                sig = "%s(%s)" % (name, args)
                out.append((kind, name, sig, line_no))
                break
    return out


# ---------------------------------------------------------------------------
# Import / dependency parsing
# ---------------------------------------------------------------------------

_IMPORT_PATTERNS = {
    "python": [
        re.compile(r"^\s*from\s+([\w.]+)\s+import\s+(?:\(([^)]+)\)|([\w.,\s*]+))"),
        re.compile(r"^\s*import\s+([\w.,\s]+)"),
    ],
    "javascript": [
        re.compile(r"^\s*import\s+(?:[\w*{},\s]+?\s+from\s+)?['\"]([^'\"]+)"
                   r"['\"]"),
        re.compile(r"^\s*import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        re.compile(r"^\s*(?:(?:const|let|var)\s+)?"
                   r"(?:[A-Za-z_$][\w$]*\s*=\s*)?"
                   r"(?:module\s*\.\s*exports\s*=\s*)?require\(\s*"
                   r"['\"]([^'\"]+)['\"]\s*\)"),
    ],
    "typescript": [
        re.compile(r"^\s*import\s+(?:[\w*{},\s]+?\s+from\s+)?['\"]([^'\"]+)"
                   r"['\"]"),
        re.compile(r"^\s*import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ],
    "go": [
        re.compile(r'^\s*([A-Za-z_]\w*)\s+"([^"]+)"'),
        re.compile(r'^\s*_\s+"([^"]+)"'),
        re.compile(r'^\s*\.\s*"([^"]+)"'),
    ],
    "java": [
        re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;"),
    ],
    "csharp": [
        re.compile(r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;"),
    ],
    "ruby": [
        re.compile(r"^\s*require\s+['\"]([^'\"]+)['\"]"),
        re.compile(r"^\s*require_relative\s+['\"]([^'\"]+)['\"]"),
    ],
    "php": [
        re.compile(r"^\s*use\s+([\w\\\\]+)"),
        re.compile(r"^\s*require(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]"),
    ],
    "rust": [
        re.compile(r"^\s*(?:pub\s+)?use\s+([\w:]+)"),
    ],
    "go_mod": [
        re.compile(r"^\s*([A-Za-z0-9_.\-/]+)\s+v?[\d.]+"),
    ],
}


def extract_imports(text, language, path=""):
    """Return [(import_target, line_no), ...] for one source file."""
    pats = _IMPORT_PATTERNS.get(language, [])
    if not pats:
        return []
    out = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        for rx in pats:
            m = rx.match(line)
            if not m:
                continue
            if language == "python" and rx is pats[0]:
                # from X import a, b -> module dep (X) plus (X.a, X.b)
                # candidates so submodules resolve to their real files.
                module = m.group(1).strip()
                names = m.group(2) or m.group(3) or ""
                out.append((module, line_no))
                # symbol candidates (also for relative imports: '. import m'
                # yields '.m', '.. import m' yields '..m') so submodules
                # resolve to their real files.
                sep = "" if module.endswith(".") else "."
                for item in names.split(","):
                    nm = re.match(r"\s*([A-Za-z_]\w*)", item)
                    if nm:
                        out.append(("%s%s%s" % (module, sep, nm.group(1)),
                                    line_no))
                break
            raw = m.group(1).strip()
            if language == "python" and "," in raw:
                parts = [p.strip() for p in raw.split(",") if p.strip()]
                for p in parts:
                    if p and not p.startswith(("*", "_")):
                        out.append((p, line_no))
            elif raw and not raw.startswith(("*", "_")):
                out.append((raw, line_no))
            break
    return out


def _module_to_relpath(module, root_top_packages):
    """Best-effort module path -> relative file path guess (python)."""
    parts = module.split(".")
    # drop the leading top-level package if it is not the project's own
    for top in root_top_packages:
        if parts[0] == top:
            rel = os.path.join(*parts)
            return rel + ".py", True
    # relative-style import already points inside the tree
    rel = os.path.join(*parts)
    return rel + ".py", False


def _resolve_relative(target, base_dir):
    """'./x' / '../x' / 'x' -> first existing candidate under base_dir.

    Strips any leading separator so os.path.join() cannot treat the
    candidate as drive-rooted on Windows (a leading '/' resets the join
    to the drive root, e.g. join(base, '/x') -> 'C:\\x').
    """
    t = target.replace("\\", "/")
    if t.startswith("./"):
        t = t[2:]
    elif t.startswith("../"):
        t = os.path.normpath(os.path.join("..", t[3:])).replace("\\", "/")
    elif t.startswith("/"):
        t = t.lstrip("/")
    t = t.lstrip("/")
    for ext in ("", ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".go",
                ".rs", ".java", ".rb", ".php", ".c", ".cpp", ".h", ".hpp",
                ".cs", ".kt", ".swift"):
        cand = os.path.normpath(os.path.join(base_dir, t + ext))
        if os.path.exists(cand):
            return cand
    return os.path.normpath(os.path.join(base_dir, t))


def _resolve_py_relative(target, base_dir):
    """Python relative import ('.', '.mod', '..mod') -> abs path or None."""
    t = target
    if t == ".":
        cand = os.path.join(base_dir, "__init__.py")
        return cand if os.path.exists(cand) else None
    n = 0
    while t.startswith("."):
        n += 1
        t = t[1:]
    base = base_dir
    for _ in range(n - 1):
        base = os.path.dirname(base)
    if not t:
        cand = os.path.join(base, "__init__.py")
        return cand if os.path.exists(cand) else None
    return _resolve_relative("./" + t, base)


def _covered_by_prefix(target, resolved_targets):
    """True when a dotted target (e.g. 'pkg.Engine') is a symbol import of
    an already-resolved module prefix (e.g. 'pkg')."""
    parts = target.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[:i]) in resolved_targets:
            return True
    return False


# ---------------------------------------------------------------------------
# Workspace index (cached, thread-safe)
# ---------------------------------------------------------------------------


class WorkspaceIndex:
    """Cached whole-workspace model: files, symbols, imports, graph edges.

    The Agent owns one instance per conversation; tools mutate/read it so
    the map persists across chat turns. Parsing is mtime-cached: only files
    that changed on disk are re-read on the next scan.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.root = None
        self.files = {}          # abs path -> file record
        self.symbols = {}        # lowercase symbol -> [(abs path, kind, sig, line)]
        self.imports = {}        # abs path -> [(target, resolved_rel, external, line)]
        self._mtime = {}         # abs path -> (mtime_ns, size)
        self._scanned_at = None

    # -- scanning --------------------------------------------------------

    def scan(self, root=".", depth=None, refresh=False):
        """Index a workspace root. Incremental: unchanged files are reused.

        Returns a dict with counts and the sorted relative file list.
        """
        root = os.path.abspath(root or ".")
        if not os.path.isdir(root):
            return {"error": "not a directory: %s" % root}
        with self._lock:
            start = time.time()
            if self.root != root or refresh:
                self.files = {}
                self.symbols = {}
                self.imports = {}
                self._mtime = {}
                self.root = root
            seen = set()
            for base, dirs, names in os.walk(root):
                depth_ok = True
                if depth is not None:
                    rel_base = os.path.relpath(base, root)
                    cur_depth = 0 if rel_base == "." else rel_base.count(os.sep) + 1
                    depth_ok = cur_depth <= int(depth)
                if depth_ok:
                    dirs[:] = [d for d in dirs
                               if not _is_ignored_dir(d) and d not in _IGNORE_DIRS]
                else:
                    dirs[:] = []
                for name in names:
                    if name in _IGNORE_FILES:
                        continue
                    full = os.path.join(base, name)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    if os.path.getsize(full) > 2 * 1024 * 1024:
                        continue  # skip huge binaries/generated blobs
                    seen.add(full)
                    if not refresh and self._mtime.get(full) == (st.st_mtime_ns, st.st_size):
                        continue
                    self._index_file(full, st)
            # drop records for files that disappeared
            for gone in [p for p in self.files if p not in seen]:
                self._drop_file(gone)
            self._scanned_at = time.time()
            files = sorted(os.path.relpath(p, root) for p in self.files)
            langs = {}
            for rec in self.files.values():
                langs[rec["lang"]] = langs.get(rec["lang"], 0) + 1
            return {
                "root": root,
                "files": len(files),
                "languages": dict(sorted(langs.items(),
                                         key=lambda kv: -kv[1])),
                "symbols": sum(len(sig) for sig in self.symbols.values()),
                "scan_ms": int((time.time() - start) * 1000),
                "tree": files,
            }

    def _index_file(self, full, st):
        lang = lang_of(full)
        rec = {
            "path": full,
            "rel": os.path.relpath(full, self.root or os.getcwd()),
            "lang": lang,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "lines": 0,
            "symbols": [],
            "imports": [],
        }
        self._mtime[full] = (st.st_mtime_ns, st.st_size)
        if lang in _SYMBOL_PATTERNS or lang in _IMPORT_PATTERNS:
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                text = ""
            rec["lines"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            rec["symbols"] = [{"kind": k, "name": n, "signature": s, "line": ln}
                              for k, n, s, ln in
                              extract_symbols(text, lang, full)]
            rec["imports"] = [{"target": t, "line": ln}
                              for t, ln in extract_imports(text, lang, full)]
        self.files[full] = rec
        for sym in rec["symbols"]:
            key = sym["name"].lower()
            self.symbols.setdefault(key, []).append(
                (full, sym["kind"], sym["signature"], sym["line"]))
        self.imports[full] = rec["imports"]

    def _drop_file(self, full):
        for key in list(self.symbols):
            self.symbols[key] = [e for e in self.symbols[key]
                                 if e[0] != full]
            if not self.symbols[key]:
                del self.symbols[key]
        self.files.pop(full, None)
        self.imports.pop(full, None)
        self._mtime.pop(full, None)

    # -- graph helpers ---------------------------------------------------

    def _top_packages(self):
        tops = {}
        for p in self.files:
            rel = os.path.relpath(p, self.root or os.getcwd()).replace("\\", "/")
            top = rel.split("/")[0]
            if top and "." not in top and "/" in rel:
                tops[top] = tops.get(top, 0) + 1
        return set(t for t, c in tops.items() if c >= 1)

    def _classify_and_resolve(self, rec):
        """For one file record, classify each import as internal/external and
        resolve internal ones to an actual file when possible."""
        base_dir = os.path.dirname(rec["path"])
        top_pkgs = self._top_packages()
        resolved = []
        for imp in rec.get("imports", []):
            target = imp["target"]
            rel_path = None
            if target.startswith(("./", "../")):
                # filesystem-relative (js/ts/other): resolve from this dir
                rel_path = _resolve_relative(target, base_dir)
                internal = os.path.exists(rel_path) or os.path.exists(
                    os.path.join(rel_path, "__init__.py"))
                if not internal:
                    rel_path = None
            elif target.startswith(".") and rec["lang"] == "python":
                # python relative import ('.', '.mod', '..mod')
                rel_path = _resolve_py_relative(target, base_dir)
                internal = bool(rel_path)
                if not internal:
                    rel_path = None
            elif target.startswith("/"):
                rel_path = _resolve_relative(target, base_dir)
                internal = os.path.exists(rel_path)
                if not internal:
                    rel_path = None
            elif "/" not in target and "." not in target and \
                    rec["lang"] in ("javascript", "typescript"):
                # bare package name (npm) - external unless it is a local dir
                internal = False
            elif rec["lang"] in ("python", "java", "csharp", "php", "go"):
                head = target.split(".")[0].split("/")[0]
                internal = head in top_pkgs or target.startswith(tuple(top_pkgs))
                if internal and rec["lang"] in ("python",):
                    cand, _ = _module_to_relpath(target, top_pkgs)
                    cand_path = os.path.join(self.root, cand)
                    if os.path.exists(cand_path):
                        rel_path = cand_path
                    else:
                        pkg = os.path.join(self.root,
                                           target.replace(".", os.sep),
                                           "__init__.py")
                        if os.path.exists(pkg):
                            rel_path = pkg
            else:
                internal = False
            resolved.append({
                "target": target,
                "internal": internal,
                "resolved": rel_path,
                "line": imp["line"],
            })
        return resolved

    # -- queries ---------------------------------------------------------

    def dependencies(self, rel_path):
        """Imports of one file: internal (resolved) + external."""
        abs_p = self._abs(rel_path)
        rec = self.files.get(abs_p)
        if not rec:
            return {"error": "file not indexed: %s" % rel_path}
        deps = self._classify_and_resolve(rec)
        internal = [{"file": os.path.relpath(d["resolved"],
                                              self.root).replace("\\", "/"),
                     "target": d["target"]}
                    for d in deps if d["internal"] and d["resolved"]]
        external = [d["target"] for d in deps if not d["internal"]]
        resolved_set = {d["target"] for d in deps
                        if d["internal"] and d["resolved"]}
        unresolved = [d["target"] for d in deps
                      if d["internal"] and not d["resolved"]
                      and not _covered_by_prefix(d["target"], resolved_set)]
        return {
            "file": rel_path,
            "imports": [d["target"] for d in deps],
            "internal_dependencies": internal,
            "external_dependencies": sorted(set(external)),
            "unresolved_internal": sorted(set(unresolved)),
        }

    def dependents(self, rel_path):
        """Reverse graph: which indexed files import this file."""
        abs_p = self._abs(rel_path)
        target_key = os.path.relpath(abs_p, self.root).replace("\\", "/")
        hits = []
        for p, rec in self.files.items():
            for d in self._classify_and_resolve(rec):
                if not d["internal"] or not d["resolved"]:
                    continue
                if os.path.relpath(d["resolved"], self.root).replace("\\", "/") == target_key:
                    hits.append(os.path.relpath(p, self.root).replace("\\", "/"))
                    break
        return {"file": rel_path, "dependents": sorted(set(hits))}

    def lookup_symbol(self, name, case_sensitive=False):
        """Where a symbol is defined, and where it is referenced.

        References are found by scanning every indexed source file's text
        for the identifier (cheap bounded scan).
        """
        key = name if case_sensitive else (name or "").lower()
        definitions = [{
            "file": os.path.relpath(p, self.root).replace("\\", "/"),
            "kind": kind, "signature": sig, "line": line,
        } for p, kind, sig, line in self.symbols.get(key, [])]
        references = []
        needle = name
        rx = re.compile(r"\b%s\b" % re.escape(needle))
        for p, rec in self.files.items():
            if rec["lang"] not in _SYMBOL_PATTERNS:
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for m in list(rx.finditer(text))[:20]:
                line = text.count("\n", 0, m.start()) + 1
                rel = os.path.relpath(p, self.root).replace("\\", "/")
                if not any(d["file"] == rel and d["line"] == line
                           for d in definitions):
                    references.append({"file": rel, "line": line})
        return {"symbol": name, "definitions": definitions,
                "references": references[:50],
                "reference_count": len(references)}

    def summary(self, limit=25):
        """Compact block injected into the system prompt for cross-turn
        awareness. Empty string when nothing has been indexed yet."""
        with self._lock:
            if not self.files:
                return ""
            rels = sorted(os.path.relpath(p, self.root).replace("\\", "/")
                          for p in self.files)
            langs = {}
            for rec in self.files.values():
                langs[rec["lang"]] = langs.get(rec["lang"], 0) + 1
            top = []
            for r in rels[:limit]:
                if "/" not in r:
                    top.append(r)
            sym_total = sum(len(v) for v in self.symbols.values())
            lang_str = ", ".join("%s(%d)" % (l, c) for l, c in
                                 sorted(langs.items(), key=lambda kv: -kv[1])[:6])
            lines = [
                "## Workspace Map (indexed: %s)" % self.root,
                "Files: %d | Symbols: %d | Languages: %s"
                % (len(rels), sym_total, lang_str or "-"),
                "Top-level: %s" % (", ".join(top[:12]) if top else "(flat)"),
                "Cross-references: use workspace_query (symbol/import lookups), "
                "workspace_deps (dependencies), workspace_symbols (signatures).",
            ]
            return "\n".join(lines)

    def to_json(self):
        """Serializable snapshot of the index."""
        with self._lock:
            return {
                "root": self.root,
                "files": [{
                    "path": rec["rel"].replace("\\", "/"),
                    "lang": rec["lang"], "size": rec["size"],
                    "lines": rec["lines"],
                    "symbols": rec["symbols"],
                    "imports": [i["target"] for i in rec["imports"]],
                } for rec in sorted(self.files.values(),
                                    key=lambda r: r["rel"])],
            }

    def _abs(self, rel_path):
        rel = (rel_path or "").replace("\\", "/").strip("/")
        p = os.path.abspath(rel) if rel else ""
        if (not p or not os.path.exists(p)) and self.root:
            p = os.path.join(self.root, *rel.split("/")) if rel else self.root
        return p


# ---------------------------------------------------------------------------
# Tool entry points
# ---------------------------------------------------------------------------

_INDEX = WorkspaceIndex()


def _get_index(index=None):
    return index or _INDEX


def tool_workspace_scan(root=".", depth=None, index=None, max_files=500):
    """Index a workspace: file tree, per-file stats, symbol/import cache."""
    idx = _get_index(index)
    try:
        res = idx.scan(root or ".", depth=depth)
    except Exception as exc:
        return "workspace_scan error: %s" % exc
    if "error" in res:
        return "workspace_scan error: %s" % res["error"]
    files = res["tree"]
    if len(files) > max_files:
        shown = files[:max_files]
        note = "\n... (%d files total, showing %d)" % (len(files), max_files)
    else:
        shown, note = files, ""
    lang_str = ", ".join("%s: %d" % (l, c) for l, c in
                         res["languages"].items())
    lines = [
        "Workspace indexed: %s" % res["root"],
        "Files: %d | Languages: %s | Symbols: %d | Scan: %dms"
        % (res["files"], lang_str or "-", res["symbols"], res["scan_ms"]),
        "",
        "File tree:",
    ]
    lines.extend("  %s" % f for f in shown)
    lines.append(note)
    lines.append("")
    lines.append("Next: workspace_symbols (signatures), workspace_deps "
                 "(import graph), workspace_query (cross-references).")
    return "\n".join(lines)


def tool_workspace_symbols(root=".", file_pattern="*", index=None,
                           max_results=300):
    """Function/class signature index for the workspace (or one file)."""
    idx = _get_index(index)
    try:
        res = idx.scan(root or ".")
    except Exception as exc:
        return "workspace_symbols error: %s" % exc
    if "error" in res:
        return "workspace_symbols error: %s" % res["error"]
    pat = (file_pattern or "*").lower()
    lines = []
    count = 0
    for rec in sorted(idx.files.values(), key=lambda r: r["rel"]):
        rel = rec["rel"].replace("\\", "/")
        if not fnmatch.fnmatch(rel.lower(), pat) and not fnmatch.fnmatch(
                os.path.basename(rel).lower(), pat):
            continue
        if not rec["symbols"]:
            continue
        lines.append("%s [%s]" % (rel, rec["lang"]))
        for s in rec["symbols"]:
            lines.append("  L%-5d %-8s %s" % (s["line"], s["kind"],
                                              s["signature"]))
            count += 1
            if count >= max_results:
                lines.append("...(symbols truncated at %d)" % max_results)
                return "\n".join(lines)
    if not lines:
        return "(no symbols found matching '%s' in %s)" % (
            file_pattern or "*", res["root"])
    return "\n".join(lines)


def tool_workspace_deps(root=".", file="", index=None):
    """Dependency graph for one file: imports + reverse dependents."""
    idx = _get_index(index)
    try:
        res = idx.scan(root or ".")
    except Exception as exc:
        return "workspace_deps error: %s" % exc
    if "error" in res:
        return "workspace_deps error: %s" % res["error"]
    if not file:
        # no file given -> top-level overview of the whole graph
        edges = []
        for rec in idx.files.values():
            rel = rec["rel"].replace("\\", "/")
            for d in idx._classify_and_resolve(rec):
                if d["internal"] and d["resolved"]:
                    edges.append("%s -> %s" % (
                        rel,
                        os.path.relpath(d["resolved"], idx.root).replace("\\", "/")))
        if not edges:
            return "(no internal import edges found in %s)" % res["root"]
        head = "Dependency graph (%d internal edges, first 100):" % len(edges)
        return "\n".join([head] + edges[:100])
    deps = idx.dependencies(file)
    if "error" in deps:
        return "workspace_deps error: %s" % deps["error"]
    rev = idx.dependents(file)
    lines = ["Dependencies of %s:" % deps["file"]]
    if deps["internal_dependencies"]:
        lines.append("Internal:")
        for d in deps["internal_dependencies"]:
            lines.append("  %s  (imported as %s)" % (d["file"], d["target"]))
    else:
        lines.append("Internal: (none)")
    lines.append("External: %s"
                 % (", ".join(deps["external_dependencies"]) or "(none)"))
    if deps["unresolved_internal"]:
        lines.append("Unresolved internal: %s"
                     % ", ".join(deps["unresolved_internal"]))
    lines.append("")
    lines.append("Files importing %s: %s"
                 % (deps["file"], ", ".join(rev["dependents"]) or "(none)"))
    return "\n".join(lines)


def tool_workspace_query(query, root=".", index=None):
    """Cross-reference query: symbol definition + usage, or file dependents."""
    idx = _get_index(index)
    try:
        res = idx.scan(root or ".")
    except Exception as exc:
        return "workspace_query error: %s" % exc
    if "error" in res:
        return "workspace_query error: %s" % res["error"]
    q = (query or "").strip()
    if not q:
        return "workspace_query error: query is required"
    # symbol lookup (identifier-ish) vs path lookup
    if re.match(r"^[\w.$-]+$", q):
        # module path (dotted or slash form) takes priority over the symbol
        # view so queries like 'app.utils' return the dependency graph.
        rel_files = {r.replace("\\", "/") for r in idx.files}
        dotted = q.replace(".", "/")
        cands = []
        for c in (q, dotted):
            cands.extend([c, c + ".py", c + ".js", c + ".ts",
                          c + "/__init__.py"])
        match = None
        for cand in cands:
            cand = cand.replace("\\", "/")
            if cand in rel_files:
                match = cand
                break
            abs_cand = os.path.join(idx.root, *cand.split("/"))
            if abs_cand in idx.files:
                match = os.path.relpath(abs_cand, idx.root).replace("\\", "/")
                break
        if match:
            deps = idx.dependencies(match)
            rev = idx.dependents(match)
            lines = ["Cross-references for module '%s':" % match]
            if deps.get("internal_dependencies"):
                lines.append("Imports:")
                for d in deps["internal_dependencies"]:
                    lines.append("  %s" % d["file"])
            lines.append("Imported by: %s"
                         % ", ".join(rev["dependents"]) or "(none)")
            if deps.get("external_dependencies"):
                lines.append("External deps: %s"
                             % ", ".join(deps["external_dependencies"]))
            return "\n".join(lines)
        sym = idx.lookup_symbol(q)
        if sym["definitions"] or sym["references"]:
            lines = ["Cross-references for '%s':" % sym["symbol"]]
            if sym["definitions"]:
                lines.append("Definitions:")
                for d in sym["definitions"]:
                    lines.append("  %s L%d [%s] %s"
                                 % (d["file"], d["line"], d["kind"],
                                    d["signature"]))
            else:
                lines.append("Definitions: (not defined in this workspace - "
                             "likely imported)")
            if sym["references"]:
                lines.append("Referenced at (%d):"
                             % sym["reference_count"])
                for r in sym["references"][:40]:
                    lines.append("  %s L%d" % (r["file"], r["line"]))
            return "\n".join(lines)
        return "workspace_query: no symbol or module '%s' found in the index" % q
    # free-form: grep across the indexed tree
    try:
        rx = re.compile(re.escape(q), re.IGNORECASE)
    except re.error:
        rx = re.compile(q)
    hits = []
    for p, rec in idx.files.items():
        if rec["lang"] not in _SYMBOL_PATTERNS:
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    if rx.search(line):
                        hits.append("%s L%d: %s"
                                    % (rec["rel"].replace("\\", "/"),
                                       line_no, line.strip()[:120]))
                        if len(hits) >= 40:
                            break
        except OSError:
            continue
        if len(hits) >= 40:
            break
    if not hits:
        return "workspace_query: no matches for '%s'" % q
    return "Matches for '%s' (%d shown):\n%s" % (
        q, len(hits), "\n".join(hits))


def tool_workspace_export(root=".", index=None):
    """Export the current workspace index as JSON (for caching/persistence)."""
    idx = _get_index(index)
    try:
        res = idx.scan(root or ".")
    except Exception as exc:
        return "workspace_export error: %s" % exc
    if "error" in res:
        return "workspace_export error: %s" % res["error"]
    import json
    return json.dumps(idx.to_json(), indent=2)
