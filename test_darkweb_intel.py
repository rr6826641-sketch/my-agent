"""Dark-web intel tool tests: scrape_onion_service + search_darkweb_leaks.

The whole network is mocked - module-level helpers (_http_get,
tor_is_available) are monkeypatched so no test ever needs a live Tor
daemon or the clearnet Ahmia index. Covers: URL gating, offline-Tor
failure modes, timeout/SSL/proxy classification, full HTML extraction
(title/meta/emails/hashes/onion links), include_text=False, the raw-HTML
attribute-email fallback, Ahmia HTML + JSON result parsing, dedupe,
limits, JSON tool wrappers, and central registry presence.

Run: py -m pytest test_darkweb_intel.py -v
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import types

import pytest
import requests

import ai_agent.tools.darkweb_intel as dw

ONION1 = ("http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu"
          "vwxyz0123456789ab.onion/leak")
ONION2 = ("http://zzyyxxwwvvuuttssrrqqppoonnmmllkkjjiihhggffeeddccbbaa0"
          "123456789ab.onion")
ONION_MIRROR = ("http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu"
                "vwxyz0123456789ab.onion/mirror")

MD5_PW = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA1_PW = "d033e22ae348aeb5660fc2140aec35850c4da997"
SHA256_PW = ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef7"
             "21d1542d8")
NOISE64 = ("aa11111111111111111111111111111111111111111111111111111111"
           "11111111")


def _resp(body_bytes, status=200, encoding="utf-8", truncated=False):
    resp = types.SimpleNamespace(content=body_bytes, encoding=encoding,
                                 status_code=status)
    resp._hackerai_body = body_bytes
    resp._hackerai_truncated = truncated
    return resp


def _fake_get(result=None, exc=None):
    def fake(url, **kwargs):
        fake.urls.append(url)
        fake.last_kwargs = kwargs
        if exc is not None:
            raise exc
        if callable(result):
            return result(url, **kwargs)
        return result
    fake.urls = []
    fake.last_kwargs = None
    return fake


def _market_page():
    return ("""<!doctype html>
<html><head>
<title>Leak Market - victim.com dump</title>
<meta name="description" content="fresh breach data for sale">
<meta name="generator" content="testgen">
</head><body>
<h1>Leak Market</h1>
<p>New dump for victim.com includes:</p>
<ul>
<li>admin@victim.com / password</li>
<li>support@victim.com</li>
</ul>
<p>hashes: MD5: %s, sha1 %s, sha256: %s</p>
<p>random hex noise %s</p>
<p>check the mirror:
<a href="%s">mirror</a>
or the clearnet <a href="https://clearnet.example.com/x">site</a>,
contact <a href="mailto:dealer@example.org">dealer</a></p>
</body></html>""" % (MD5_PW, SHA1_PW, SHA256_PW, NOISE64,
                      ONION_MIRROR)).encode("utf-8")


@pytest.fixture
def tor_up(monkeypatch):
    monkeypatch.setattr(dw, "tor_is_available",
                        lambda timeout=2.0: (True, "test tor up"))


# ---------------------------------------------------------- URL gating

def test_scrape_missing_url_errors():
    out = dw.scrape_onion_service("")
    assert out["status"] == "error"
    assert "onion_url" in out["error"]


def test_scrape_rejects_clearnet_and_bad_schemes():
    for url in ("https://example.com/x", "http://sub.example.org",
                "ftp://x.onion/y", "file:///etc/passwd"):
        out = dw.scrape_onion_service(url)
        assert out["status"] == "error", url
    out = dw.scrape_onion_service("x.onion/y")
    assert out["status"] == "error"
    assert "onion" in out["error"].lower()


# ----------------------------------------------------- offline-Tor modes

def test_scrape_tor_offline_error(monkeypatch):
    monkeypatch.setattr(dw, "tor_is_available",
                        lambda timeout=2.0: (False, "connection refused"))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "error"
    assert out["error"] == "Tor proxy offline"
    assert "TOR_PROXY" in out["hint"]
    assert "elapsed_ms" in out


def test_search_tor_offline_error(monkeypatch):
    monkeypatch.setattr(dw, "tor_is_available",
                        lambda timeout=2.0: (False, "refused"))
    out = dw.search_darkweb_leaks("victim.com", use_tor=True)
    assert out["status"] == "error"
    assert "Tor proxy offline" in out["error"]
    assert "use_tor=false" in out["hint"]


# --------------------------------------------------- transport failures

def test_scrape_timeout_classified(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(exc=requests.exceptions.Timeout()))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "error"
    assert "offline or too slow" in out["error"]
    assert "retry" in out["hint"]


def test_scrape_ssl_classified(monkeypatch, tor_up):
    exc = requests.exceptions.SSLError("cert verify failed")
    monkeypatch.setattr(dw, "_http_get", _fake_get(exc=exc))
    out = dw.scrape_onion_service(ONION1, ignore_ssl=False)
    assert out["status"] == "error"
    assert "TLS error" in out["error"]
    assert "ignore_ssl=true" in out["hint"]


def test_scrape_proxy_error_classified(monkeypatch, tor_up):
    exc = requests.exceptions.ProxyError("socks5 handshake died")
    monkeypatch.setattr(dw, "_http_get", _fake_get(exc=exc))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "error"
    assert "Tor proxy failed" in out["error"]
    assert "9050" in out["hint"]


def test_scrape_generic_request_exception(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(exc=requests.exceptions.ConnectionError()))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "error"
    assert "request failed" in out["error"]


# ------------------------------------------------------ full extraction

def test_scrape_extracts_intel(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(_market_page())))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "ok"
    assert out["url"] == ONION1
    assert out["http_status"] == 200
    assert out["onion_host"].endswith(".onion")
    assert out["title"] == "Leak Market - victim.com dump"
    assert out["page_meta"]["description"] == "fresh breach data for sale"
    assert out["page_meta"]["generator"] == "testgen"
    assert ONION_MIRROR in out["onion_links"]
    assert out["onion_link_count"] == 1
    assert "clearnet.example.com" not in json.dumps(out["onion_links"])
    assert "admin@victim.com" in out["emails_found"]
    assert "support@victim.com" in out["emails_found"]
    assert out["email_count"] == 2
    ha = out["hash_analysis"]
    assert MD5_PW in ha["labeled"] and MD5_PW in ha["by_type"]["md5"]
    assert SHA1_PW in ha["by_type"]["sha1"]
    assert SHA256_PW in ha["by_type"]["sha256"]
    assert ha["counts"]["md5"] >= 1 and ha["counts"]["sha256"] >= 1
    assert NOISE64 in ha["generic_hex_candidates"]
    assert NOISE64 not in ha["labeled"]
    assert "New dump for victim.com" in out["text_excerpt"]
    assert out["word_count"] > 5
    assert out["download_truncated"] is False


def test_scrape_uses_tor_proxy_and_timeout(monkeypatch, tor_up):
    fake = _fake_get(result=_resp(b"<html><title>T</title></html>"))
    monkeypatch.setattr(dw, "_http_get", fake)
    dw.scrape_onion_service(ONION1, timeout=30)
    assert fake.urls == [ONION1]
    kw = fake.last_kwargs
    assert kw["proxies"] == {"http": dw.tor_proxy(),
                             "https": dw.tor_proxy()}
    assert kw["timeout"] == 30.0
    assert kw["verify"] is True


def test_scrape_truncation_flag(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(b"<html>x</html>",
                                               truncated=True)))
    out = dw.scrape_onion_service(ONION1)
    assert out["download_truncated"] is True


def test_scrape_http_error_still_classified(monkeypatch, tor_up):
    body = (b"<html><head><title>gone</title></head>"
            b"<body>not here anymore</body></html>")
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(body, status=404)))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "http_error"
    assert "HTTP 404" in out["error"]


def test_scrape_include_text_false_skips_content(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(_market_page())))
    out = dw.scrape_onion_service(ONION1, include_text=False)
    assert out["status"] == "ok"
    assert out["title"] == "Leak Market - victim.com dump"
    assert ONION_MIRROR in out["onion_links"]
    assert "emails_found" not in out
    assert "email_count" not in out
    assert "hash_analysis" not in out
    assert "text_excerpt" not in out


def test_scrape_attribute_email_fallback(monkeypatch, tor_up):
    # e-mail lives only in an attribute -> readable-text pass misses it,
    # the raw-HTML second pass must catch it.
    body = (b"<html><head><title>attr page</title></head><body>"
            b"<p>no visible emails here</p>"
            b"<a href='mailto:attrleak@victim.com'>contact</a>"
            b"</body></html>")
    monkeypatch.setattr(dw, "_http_get", _fake_get(result=_resp(body)))
    out = dw.scrape_onion_service(ONION1)
    assert "attrleak@victim.com" in out["emails_found"]
    assert out["email_count"] == 1


def test_scrape_binary_body_no_crash(monkeypatch, tor_up):
    body = bytes([0, 1, 255, 254]) + b" body"
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(body)))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "ok"
    assert out["downloaded_bytes"] == 9


def test_scrape_empty_body_no_crash(monkeypatch, tor_up):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(b"")))
    out = dw.scrape_onion_service(ONION1)
    assert out["status"] == "ok"
    assert out["downloaded_bytes"] == 0
    assert "body_preview" in out

# --------------------------------------------------- Ahmia HTML search

AHMIA_HITS = [
    (ONION1, "Victim Corp leak dump",
     "Indexed 2021-03-14 - full dump of victim.com"),
    (ONION2, "second market",
     "added 2021/05/02 victim.com records for sale"),
]


def _ahmia_html():
    lis = "\n".join(
        '<li class="result"><h4><a href="%s">%s</a></h4>'
        '<p class="url">%s</p><p>%s</p></li>'
        % (url, title, url, snippet) for url, title, snippet in AHMIA_HITS)
    return ("<html><body><h1>results</h1><ol>%s</ol>"
            "<a href='https://ahmia.fi'>ahmia itself</a>"
            "<a href='https://clearnet.example.com/x'>clearnet</a>"
            "</body></html>" % lis).encode("utf-8")


def test_search_html_parses_hits(monkeypatch):
    fake = _fake_get(result=_resp(_ahmia_html()))
    monkeypatch.setattr(dw, "_http_get", fake)
    out = dw.search_darkweb_leaks("victim.com")
    assert out["status"] == "ok"
    assert out["engine"] == "ahmia" and out["via_tor"] is False
    assert out["result_count"] == 2
    first = out["results"][0]
    assert set(first) == {"onion_url", "title", "snippet",
                          "first_seen_timestamp"}
    assert first["onion_url"] == ONION1
    assert first["title"] == "Victim Corp leak dump"
    assert first["first_seen_timestamp"] == "2021-03-14"
    assert "victim.com" in first["snippet"]
    assert out["results"][1]["first_seen_timestamp"] == "2021-05-02"
    # clearnet mirror itself is never a hit
    assert all("ahmia.fi" not in r["onion_url"]
               for r in out["results"])
    # clearnet default must NOT route through a proxy
    assert fake.last_kwargs["proxies"] is None


def test_search_limit_respected(monkeypatch):
    fake = _fake_get(result=_resp(_ahmia_html()))
    monkeypatch.setattr(dw, "_http_get", fake)
    out = dw.search_darkweb_leaks("victim.com", limit=1)
    assert out["result_count"] == 1
    assert out["results"][0]["onion_url"] == ONION1


def test_search_use_tor_routes_via_proxy(monkeypatch, tor_up):
    fake = _fake_get(result=_resp(_ahmia_html()))
    monkeypatch.setattr(dw, "_http_get", fake)
    out = dw.search_darkweb_leaks("victim.com", use_tor=True)
    assert out["via_tor"] is True
    assert ("juhanurmihxlp77nkq76byazcldxy2hl43fwsa2icpv3kqon4m5c5b2yd"
            ".onion") in fake.urls[0]
    assert fake.last_kwargs["proxies"]["http"] == dw.tor_proxy()


def test_search_deduplicates_repeated_href(monkeypatch):
    dup = ("<li class='result'><a href='%s'>one</a></li>"
           "<li class='result'><a href='%s'>again</a></li>" % (ONION1,
                                                               ONION1))
    monkeypatch.setattr(dw, "_http_get", _fake_get(result=_resp(dup)))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["result_count"] == 1


# ---------------------------------------------------- Ahmia JSON mode

def test_search_json_results(monkeypatch):
    body = json.dumps({"results": [
        {"url": ONION1, "title": "json hit",
         "snippet": "creds for victim.com", "first_seen": "2020-01-02"},
        {"url": "https://clearnet.example.com/x", "title": "skip"},
    ]}).encode("utf-8")
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(body)))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["result_count"] == 1
    hit = out["results"][0]
    assert hit["onion_url"] == ONION1
    assert hit["first_seen_timestamp"] == "2020-01-02"


def test_search_json_epoch_ms_timestamp(monkeypatch):
    body = json.dumps({"results": [
        {"url": ONION1, "title": "t", "snippet": "s",
         "first_seen": 1577923200000},
    ]}).encode("utf-8")
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(body)))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["results"][0]["first_seen_timestamp"] == "2020-01-02"


# ------------------------------------------------- search edge cases

def test_search_empty_query_errors():
    out = dw.search_darkweb_leaks("   ")
    assert out["status"] == "error"
    assert "query" in out["error"]


def test_search_timeout_classified(monkeypatch):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(exc=requests.exceptions.Timeout()))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["status"] == "error"
    assert "timed out" in out["error"]


def test_search_transport_error_classified(monkeypatch):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(exc=requests.exceptions.ConnectionError()))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["status"] == "error"
    assert "search request failed" in out["error"]


def test_search_empty_body_error(monkeypatch):
    monkeypatch.setattr(dw, "_http_get", _fake_get(result=_resp(b"")))
    out = dw.search_darkweb_leaks("victim.com")
    assert out["status"] == "error"
    assert "empty body" in out["error"]


def test_search_limit_clamped(monkeypatch):
    monkeypatch.setattr(dw, "_http_get",
                        _fake_get(result=_resp(_ahmia_html())))
    out = dw.search_darkweb_leaks("victim.com", limit=999)
    assert out["status"] == "ok"


# ------------------------------------------------- JSON tool wrappers

def test_tool_wrappers_return_json_strings(monkeypatch):
    monkeypatch.setattr(dw, "tor_is_available",
                        lambda timeout=2.0: (False, "refused"))
    raw = dw.tool_scrape_onion_service(ONION1)
    assert isinstance(raw, str)
    assert json.loads(raw)["status"] == "error"
    raw = dw.tool_search_darkweb_leaks("victim.com", use_tor=True)
    assert isinstance(raw, str)
    assert json.loads(raw)["status"] == "error"


def test_tool_search_wrapper_full_path(monkeypatch):
    fake = _fake_get(result=_resp(_ahmia_html()))
    monkeypatch.setattr(dw, "_http_get", fake)
    raw = dw.tool_search_darkweb_leaks("victim.com")
    data = json.loads(raw)
    assert data["result_count"] == 2
    assert data["results"][0]["onion_url"].startswith("http")


# ------------------------------------------------- registry integration

def test_registry_contains_both_tools():
    from ai_agent.tools import create_tools

    class _Mem:
        def get(self, key, default=None):
            return default
        def set(self, key, value):
            return None

    tools = {t.name: t for t in create_tools(_Mem())}
    assert "scrape_onion_service" in tools
    assert "search_darkweb_leaks" in tools
    sc = tools["scrape_onion_service"].schema()["function"]["parameters"]
    assert sc["required"] == ["onion_url"]
    assert "ignore_ssl" in sc["properties"]
    assert sc["properties"]["include_text"]["default"] is True
    sd = tools["search_darkweb_leaks"].schema()["function"]["parameters"]
    assert sd["required"] == ["query"]
    assert sd["properties"]["limit"]["default"] == 8
    assert sd["properties"]["use_tor"]["default"] is False
