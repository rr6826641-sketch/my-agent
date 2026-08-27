"""File & data tools: search, grep, hashing, JSON/CSV, archives, diffs."""

import csv
import difflib
import fnmatch
import hashlib
import io
import json
import os
import shutil
import zipfile
import tarfile


def tool_search_files(pattern="*", path=".", max_results=50):
    """Find files whose name matches a glob pattern."""
    try:
        hits = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
            for name in files:
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    full = os.path.join(root, name)
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = 0
                    hits.append("%s (%d bytes)" % (full, size))
                    if len(hits) >= max_results:
                        break
            if len(hits) >= max_results:
                break
        if not hits:
            return "(no files matching '%s' under %s)" % (pattern, path)
        out = "\n".join(hits)
        return out + "\n... (%d total, showing %d)" % (len(hits), min(len(hits), max_results)) if len(hits) > max_results else out
    except Exception as exc:
        return "search_files error: %s" % exc


def tool_grep_files(pattern, path=".", file_pattern="*", max_results=30, max_chars=2000):
    """Search text inside files for a regex pattern."""
    import re
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return "grep_files error: bad regex: %s" % exc
    try:
        hits = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
            for name in files:
                if not fnmatch.fnmatch(name.lower(), file_pattern.lower()):
                    continue
                full = os.path.join(root, name)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        for line_no, line in enumerate(f, 1):
                            if rx.search(line):
                                snippet = line.strip()[:max_chars]
                                hits.append("%s:%d: %s" % (full, line_no, snippet))
                                if len(hits) >= max_results:
                                    break
                except Exception:
                    continue
                if len(hits) >= max_results:
                    break
            if len(hits) >= max_results:
                break
        if not hits:
            return "(no matches for '%s' under %s)" % (pattern, path)
        return "\n".join(hits) + ("\n... more" if len(hits) == max_results else "")
    except Exception as exc:
        return "grep_files error: %s" % exc


def tool_file_info(path):
    if not os.path.exists(path):
        return "file_info: not found: %s" % path
    try:
        st = os.stat(path)
        lines = ["path: %s" % path,
                 "type: %s" % ("directory" if os.path.isdir(path) else "file"),
                 "size: %d bytes (%.2f KB)" % (st.st_size, st.st_size / 1024),
                 "created: %s" % datetime_from_ts(st.st_ctime),
                 "modified: %s" % datetime_from_ts(st.st_mtime),
                 "accessed: %s" % datetime_from_ts(st.st_atime),
                 "mode: %s" % oct(st.st_mode)]
        if os.path.isfile(path):
            ext = os.path.splitext(path)[1]
            with open(path, "rb") as f:
                head = f.read(16)
            lines.append("extension: %s" % (ext or "(none)"))
            lines.append("magic bytes: %s" % head.hex())
        return "\n".join(lines)
    except Exception as exc:
        return "file_info error: %s" % exc


def datetime_from_ts(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _hash_bytes(data):
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest()}


def tool_hash_file(path):
    if not os.path.isfile(path):
        return "hash_file: not a file: %s" % path
    try:
        h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
             "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for algo in h.values():
                    algo.update(chunk)
        return "\n".join("%s  %s" % (name.upper(), algo.hexdigest())
                         for name, algo in h.items())
    except Exception as exc:
        return "hash_file error: %s" % exc


def tool_json_format(text=None, path=None):
    try:
        if path:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        if not text:
            return "json_format: provide text or path"
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2, ensure_ascii=False)
    except json.JSONDecodeError as exc:
        return "json_format: invalid JSON: %s" % exc
    except Exception as exc:
        return "json_format error: %s" % exc


def tool_csv_preview(path, max_rows=15):
    if not os.path.isfile(path):
        return "csv_preview: not found: %s" % path
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            rows = list(csv.reader(f))
        if not rows:
            return "(empty CSV)"
        width = len(rows[0])
        lines = ["%d columns, %d rows" % (width, len(rows))]
        for i, row in enumerate(rows[:max_rows]):
            cells = [c[:40] for c in row]
            lines.append("row %d: %s" % (i, " | ".join(cells)))
        if len(rows) > max_rows:
            lines.append("... %d more rows" % (len(rows) - max_rows))
        return "\n".join(lines)
    except Exception as exc:
        return "csv_preview error: %s" % exc


def tool_create_archive(target_path, source_path):
    """Zip a file or directory into target_path."""
    try:
        base = os.path.basename(source_path.rstrip("/\\")) or "archive"
        if os.path.isdir(source_path):
            with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(source_path):
                    for name in files:
                        full = os.path.join(root, name)
                        arc = os.path.join(base, os.path.relpath(full, source_path))
                        zf.write(full, arc)
        elif os.path.isfile(source_path):
            with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(source_path, base)
        else:
            return "create_archive: source not found: %s" % source_path
        return "created %s (%d bytes)" % (target_path, os.path.getsize(target_path))
    except Exception as exc:
        return "create_archive error: %s" % exc


def tool_extract_archive(archive_path, dest_dir=None):
    """Extract zip/tar/tar.gz into dest_dir (default: same folder)."""
    try:
        if not os.path.isfile(archive_path):
            return "extract_archive: not found: %s" % archive_path
        dest = dest_dir or os.path.splitext(archive_path)[0]
        os.makedirs(dest, exist_ok=True)
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(dest)
            return "extracted zip to %s (%d entries)" % (dest, len(zf.namelist()))
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as tf:
                tf.extractall(dest)
            return "extracted tar to %s (%d entries)" % (dest, len(tf.getnames()))
        return "extract_archive: unsupported archive format"
    except Exception as exc:
        return "extract_archive error: %s" % exc


def tool_diff_text(text_a, text_b, path_a=None, path_b=None, context=3):
    """Diff two strings or two files."""
    try:
        if path_a:
            with open(path_a, "r", encoding="utf-8", errors="replace") as f:
                text_a = f.read()
        if path_b:
            with open(path_b, "r", encoding="utf-8", errors="replace") as f:
                text_b = f.read()
        if text_a is None or text_b is None:
            return "diff_text: provide text_a/text_b or path_a/path_b"
        a_lines = text_a.splitlines()
        b_lines = text_b.splitlines()
        diff = list(difflib.unified_diff(
            a_lines, b_lines,
            fromfile=path_a or "text_a", tofile=path_b or "text_b",
            lineterm="", n=context))
        if not diff:
            return "(no differences)"
        return "\n".join(diff[:200]) + ("\n... more" if len(diff) > 200 else "")
    except Exception as exc:
        return "diff_text error: %s" % exc


def tool_pdf_info(path):
    """Extract basic info from a PDF by parsing raw bytes (no external lib)."""
    if not os.path.isfile(path):
        return "pdf_info: not found: %s" % path
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
            if not head.startswith(b"%PDF"):
                return "pdf_info: not a valid PDF (bad header)"
            f.seek(0, 2)
            size = f.tell()
            if size <= 10 * 1024 * 1024:
                f.seek(0)
                body = f.read()
            else:
                f.seek(0)
                body = f.read(10 * 1024 * 1024)
                f.seek(max(0, size - 1024 * 1024))
                body += f.read(1024 * 1024)
        import re
        text = body.decode("latin-1", errors="replace")
        pages = len(re.findall(r"/Type\s*/Page[^s]", text))
        title = re.search(r"/Title\s*\(([^)]{1,200})\)", text)
        producer = re.search(r"/Producer\s*\(([^)]{1,120})\)", text)
        creator = re.search(r"/Creator\s*\(([^)]{1,120})\)", text)
        version = re.search(rb"%PDF-(\d\.\d)", head)
        lines = ["path: %s" % path,
                 "size: %d bytes (%.1f KB)" % (size, size / 1024),
                 "version: %s" % (version.group(1).decode() if version else "?"),
                 "pages (approx): %d" % pages]
        if title:
            lines.append("title: %s" % title.group(1))
        if creator:
            lines.append("creator: %s" % creator.group(1))
        if producer:
            lines.append("producer: %s" % producer.group(1))
        return "\n".join(lines)
    except Exception as exc:
        return "pdf_info error: %s" % exc


def tool_image_info(path):
    """Image dimensions/format by parsing headers (no external lib)."""
    import struct
    if not os.path.isfile(path):
        return "image_info: not found: %s" % path
    try:
        with open(path, "rb") as f:
            data = f.read(64)
        size = os.path.getsize(path)
        if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
            w, h = struct.unpack(">II", data[16:24])
            return "PNG image: %dx%d, %d bytes" % (w, h, size)
        if data[:2] == b"\xff\xd8":
            # scan JPEG markers for SOF (SOF0-3, SOF5-7, SOF9-11, SOF13-15)
            import re as _re
            with open(path, "rb") as f:
                blob = f.read(300000)
            for m in _re.finditer(rb"\xff\xc[0-9a-f]", blob):
                marker = m.group(0)[1]
                if marker in (0xC4, 0xC8, 0xCC):
                    continue  # DHT, JPG, DAC - not SOF
                pos = m.start()
                if pos + 8 > len(blob):
                    break
                h = struct.unpack(">H", blob[pos + 4:pos + 6])[0]
                w = struct.unpack(">H", blob[pos + 6:pos + 8])[0]
                return "JPEG image: %dx%d, %d bytes" % (w, h, size)
            return "JPEG image: dimensions unknown, %d bytes" % size
        if data[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", data[6:10])
            return "GIF image: %dx%d, %d bytes" % (w, h, size)
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "WEBP image: %d bytes" % size
        if data[:2] == b"BM":
            w, h = struct.unpack("<ii", data[18:26])
            return "BMP image: %dx%d, %d bytes" % (abs(w), abs(h), size)
        return "image_info: unknown format, %d bytes, magic=%s" % (size, data[:8].hex())
    except Exception as exc:
        return "image_info error: %s" % exc
