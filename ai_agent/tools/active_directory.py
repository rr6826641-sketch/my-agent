"""Active Directory & Internal Network Pivoting Tools.

Tools:
  - smb_enum(target_ip, port=445): SMB share probing, null-session checks,
    SMB1/SMB2 protocol version negotiation details.
  - ldap_search_anonymous(target_ip, base_dn=""): anonymous LDAP queries
    against the root DSE / a base DN to enumerate naming contexts and
    exposed directory objects.
  - kerberos_ticket_check(target_ip, domain): raw AS-REQ probes on port 88
    to fingerprint the KDC and detect AS-REP roasting opportunities.
  - subnet_sweep(subnet_cidr, ports=[80,445,3389,22]): rapid parallel host
    discovery across an internal CIDR block.

Design rules: every function returns a clean JSON-serialisable dict, never
raises, uses non-blocking socket timeouts, and falls back gracefully when a
protocol is not spoken or a host is unreachable.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from .base import truncate

DEFAULT_TIMEOUT = 3.0
_MAX_SWEEP_HOSTS = 8192


def _err(msg):
    return {"error": msg}


def _tcp_banner(host, port, timeout=DEFAULT_TIMEOUT, send=b"", read=4096):
    """TCP connect, optionally send bytes, return raw response (or b'')."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            try:
                return s.recv(read)
            except socket.timeout:
                return b""
    except (OSError, socket.timeout):
        return b""


def _tcp_open(host, port, timeout=DEFAULT_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# BER / ASN.1 helpers (minimal, DER-style)
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


def _ber_seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _ber_octets(s):
    if isinstance(s, str):
        s = s.encode()
    return _tlv(0x04, s)


def _ber_enum(v):
    return _tlv(0x0A, bytes([v]))


def _ber_bool(v):
    return _tlv(0x01, b"\xff" if v else b"\x00")


def _ber_ctx(tag, payload, constructed=True):
    base = 0xA0 if constructed else 0x80
    return _tlv(base | tag, payload)


def _ber_read(data, offset=0):
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    return tag, data[offset:offset + length], offset + length


def _ber_iter(data):
    offset = 0
    while offset < len(data):
        tag, payload, offset = _ber_read(data, offset)
        yield tag, payload


def _ldap_msg(msgid, app_pdu):
    return _ber_seq(_ber_int(msgid), app_pdu)


# SMB enumeration
_SMB2_DIALECTS = {
    0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2",
    0x0311: "3.1.1",
}
_SMB1_DIALECTS = {
    0x00: "PC NETWORK PROGRAM 1.0", 0x01: "PCLAN1.0", 0x02: "PCLAN1.2",
    0x03: "LM1.2X002", 0x04: "LANMAN1.0", 0x05: "LANMAN1.2",
    0x06: "NT LM 0.12", 0x07: "NT LM 0.12 (NT LANMAN 1.0)", 0x0D: "SMB 1.0",
}


def _smb2_negotiate_pkt():
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[8:12] = (0).to_bytes(4, "little")
    header[12:14] = (0).to_bytes(2, "little")          # Command = NEGOTIATE
    header[18:20] = (1).to_bytes(2, "little")
    header[24:32] = (0).to_bytes(8, "little")
    header[32:36] = (0xFEFF).to_bytes(4, "little")
    header[40:48] = (0).to_bytes(8, "little")
    body = bytearray()
    body += (36).to_bytes(2, "little")                 # StructureSize
    body += (3).to_bytes(2, "little")                  # DialectCount
    body += (1).to_bytes(2, "little")                  # SIGNING_ENABLED
    body += (0).to_bytes(2, "little")
    body += (0).to_bytes(4, "little")                  # Capabilities
    body += os.urandom(16)                             # ClientGuid
    body += (0).to_bytes(4, "little")                  # NegotiateContextOffset
    body += (0).to_bytes(2, "little")                  # NegotiateContextCount
    body += (0).to_bytes(2, "little")
    for d in (0x0202, 0x0210, 0x0311):
        body += d.to_bytes(2, "little")
    return bytes(header) + bytes(body)


def _smb1_header(command, flags2=0x0001):
    h = bytearray(32)
    h[0:4] = b"\xffSMB"
    h[4] = command
    h[9] = 0x18
    h[10:12] = flags2.to_bytes(2, "little")
    h[26:28] = (0x1234).to_bytes(2, "little")
    return h


def _smb1_negotiate_pkt():
    return bytes(_smb1_header(0x72)) + b"\x00\x00\x00"


def _smb1_session_setup_pkt():
    h = _smb1_header(0x73, flags2=0x0001)
    body = b"\x0d"                                     # WordCount = 13
    body += b"\xff"                                    # AndXCommand = none
    body += b"\x00"
    body += (0).to_bytes(2, "little")                  # AndXOffset
    body += (0xFFFF).to_bytes(2, "little")             # MaxBufferSize
    body += (1).to_bytes(2, "little")                  # MaxMpxCount
    body += (1).to_bytes(2, "little")                  # VcNumber
    body += (0).to_bytes(4, "little")                  # SessionKey
    body += (0).to_bytes(2, "little")                  # SecurityBlobLength
    body += (0).to_bytes(4, "little")                  # Reserved
    body += (0x00000004 | 0x00000080 | 0x00000100).to_bytes(4, "little")
    body += (4).to_bytes(2, "little")                  # ByteCount
    body += b"\x00\x00\x00\x00"                        # empty UNICODE strings
    return bytes(h) + body


def _smb1_tree_connect_pkt(host, share):
    h = _smb1_header(0x75, flags2=0x0001)
    path = ("\\\\" + host + "\\" + share).encode("utf-16-le") + b"\x00\x00"
    svc = share.encode("utf-16-le") + b"\x00\x00"
    body = b"\x04"                                     # WordCount = 4
    body += b"\xff"
    body += b"\x00"
    body += (0).to_bytes(2, "little")
    body += (0).to_bytes(2, "little")                  # Flags
    body += (0).to_bytes(2, "little")                  # PasswordLength
    body += (len(path) + len(svc)).to_bytes(2, "little")
    body += path + svc
    return bytes(h) + body


def _smb1_response_ok(resp):
    if len(resp) < 36 or resp[:4] != b"\xffSMB":
        return False
    return resp[5] == 0 and resp[7:9] == b"\x00\x00"


# SMB2 / NTLMSSP deep null-session probing (single-TCP-connection session
# setup + tree connect over an anonymous NTLMSSP exchange)
_NTLM_ANON_FLAGS = (0x00000001 | 0x00000002 | 0x00000200 | 0x00000800 |
                    0x00800000 | 0x02000000 | 0x20000000 | 0x80000000)
_AV_NAMES = {
    1: "ntlm_netbios_computer", 2: "ntlm_netbios_domain",
    3: "ntlm_dns_computer", 4: "ntlm_dns_domain", 5: "ntlm_dns_forest",
    7: "ntlm_timestamp",
}


def _netbios_wrap(payload):
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _netbios_unwrap(data):
    """Strip the 4-byte RFC 1002 session header from a raw TCP reply
    if the server framed it (direct TCP 445/139 replies are wrapped)."""
    if len(data) >= 4 and data[0] == 0:
        n = int.from_bytes(data[1:4], "big")
        if n >= len(data) - 4:
            return data[4:]
    return data


def _recv_netbios_msg(s):
    """Read one length-prefixed SMB2 message from the socket."""
    header = b""
    try:
        while len(header) < 4:
            chunk = s.recv(4 - len(header))
            if not chunk:
                return b""
            header += chunk
        length = int.from_bytes(header[1:4], "big")
        body = b""
        while len(body) < length:
            chunk = s.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
        return body
    except (OSError, socket.timeout):
        return b""


def _smb2_parse_negotiate(resp):
    """Extract dialect / security mode / server GUID from an SMB2
    NEGOTIATE response. Returns {} on truncation, {'status': n} on error."""
    try:
        if resp[:4] != b"\xfeSMB" or len(resp) < 72:
            return {}
        status = int.from_bytes(resp[8:12], "little")
        if status != 0:
            return {"status": status}
        dialect = int.from_bytes(resp[68:70], "little")
        return {
            "dialect": _SMB2_DIALECTS.get(dialect, "0x%04x" % dialect),
            "signing_required": bool(int.from_bytes(resp[66:68], "little") & 0x02),
            "server_guid": resp[72:88].hex() if len(resp) >= 88 else "",
        }
    except Exception:
        return {}


def _ntlmssp_type1_pkt():
    msg = b"NTLMSSP\x00" + (1).to_bytes(4, "little")
    msg += _NTLM_ANON_FLAGS.to_bytes(4, "little")
    msg += (0).to_bytes(2, "little") * 6            # domain + workstation fields
    msg += b"\x06\x00\xb0\x0f\x00\x00\x00\x0f"      # version 6.0 build 6000
    return msg


def _ntlmssp_parse_type2(blob):
    """Parse an NTLMSSP CHALLENGE (type 2) blob."""
    out = {}
    try:
        if len(blob) < 32 or blob[:8] != b"NTLMSSP\x00":
            return out
        if int.from_bytes(blob[8:12], "little") != 2:
            return out
        out["ntlm_server_challenge"] = blob[24:32].hex()
        tn_len = int.from_bytes(blob[12:14], "little")
        tn_off = int.from_bytes(blob[16:18], "little")
        if tn_len and tn_off + tn_len <= len(blob):
            out["ntlm_target_name"] = blob[tn_off:tn_off + tn_len].decode(
                "utf-16-le", "replace")
        ti_len = int.from_bytes(blob[40:42], "little")
        ti_off = int.from_bytes(blob[44:46], "little")
        if ti_len and ti_off + ti_len <= len(blob):
            pos, end = ti_off, ti_off + ti_len
            while pos + 4 <= end:
                av_type = int.from_bytes(blob[pos:pos + 2], "little")
                av_len = int.from_bytes(blob[pos + 2:pos + 4], "little")
                if av_type == 0:
                    break
                name = _AV_NAMES.get(av_type, "ntlm_av_%d" % av_type)
                out[name] = blob[pos + 4:pos + 4 + av_len].decode(
                    "utf-16-le", "replace")
                pos += 4 + av_len
    except Exception:
        pass
    return out


def _ntlmssp_type3_pkt():
    """Empty-credential (anonymous) NTLMSSP AUTH message."""
    msg = b"NTLMSSP\x00" + (3).to_bytes(4, "little")
    for _ in range(6):                               # LM, NTLM, domain, user,
        msg += (0).to_bytes(2, "little") * 3         # workstation, session key
    msg += _NTLM_ANON_FLAGS.to_bytes(4, "little")
    msg += b"\x06\x00\xb0\x0f\x00\x00\x00\x0f"
    return msg


def _smb2_session_setup_pkt(session_id, token, msgid=1):
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (1).to_bytes(2, "little")         # Command = SESSION_SETUP
    header[24:32] = msgid.to_bytes(8, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    body = bytearray()
    body += (9).to_bytes(2, "little")                 # StructureSize = 9
    body += (0).to_bytes(1, "little")                 # Flags (VcNumber)
    body += (1).to_bytes(1, "little")                 # SecurityMode = signing enabled
    body += (0).to_bytes(4, "little")                 # Capabilities
    body += (0).to_bytes(4, "little")                 # Channel
    body += (64 + 24).to_bytes(2, "little")           # SecurityBufferOffset = 88
    body += len(token).to_bytes(2, "little")          # SecurityBufferLength
    body += (0).to_bytes(8, "little")                 # PreviousSessionId
    return bytes(header) + bytes(body) + token


def _smb2_tree_connect_pkt(session_id, host, share, msgid):
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (3).to_bytes(2, "little")         # Command = TREE_CONNECT
    header[24:32] = msgid.to_bytes(8, "little")
    header[40:48] = session_id.to_bytes(8, "little")
    path = ("\\\\" + host + "\\" + share).encode("utf-16-le")
    body = (9).to_bytes(2, "little")                  # StructureSize = 9
    body += (64 + 8).to_bytes(2, "little")            # PathOffset
    body += (0).to_bytes(2, "little")                 # Reserved
    body += len(path).to_bytes(2, "little")           # PathLength
    return bytes(header) + body + path


def _smb2_null_session_probe(host, port, shares, timeout=DEFAULT_TIMEOUT):
    """Deep SMB2 anonymous probe over one TCP session: NTLMSSP type-1/type-2
    exchange, empty-credential session setup, then tree-connects to each
    share on the established anonymous session."""
    info = {"smb2_session_setup": False, "smb2_anonymous_shares": [],
            "smb2_share_types": {}, "smb2_share_errors": {}}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    except (OSError, socket.timeout) as exc:
        info["error"] = "connection failed: %s" % exc
        return info
    try:
        s.sendall(_netbios_wrap(_smb2_negotiate_pkt()))
        resp = _recv_netbios_msg(s)
        if resp[:4] != b"\xfeSMB" or len(resp) < 68 or \
                int.from_bytes(resp[8:12], "little") != 0:
            info["error"] = "SMB2 negotiate failed during null-session probe"
            return info
        s.sendall(_netbios_wrap(
            _smb2_session_setup_pkt(0, _ntlmssp_type1_pkt())))
        resp = _recv_netbios_msg(s)
        if resp[:4] != b"\xfeSMB" or len(resp) < 72:
            info["error"] = "no SMB2 reply to session setup (NTLMSSP type 1)"
            return info
        status = int.from_bytes(resp[8:12], "little")
        sid = int.from_bytes(resp[40:48], "little")
        blob = b""
        try:
            sbuf_off = int.from_bytes(resp[68:70], "little")
            sbuf_len = int.from_bytes(resp[70:72], "little")
            if sbuf_len and sbuf_off + sbuf_len <= len(resp):
                blob = resp[sbuf_off:sbuf_off + sbuf_len]
        except Exception:
            blob = b""
        if blob:
            info.update(_ntlmssp_parse_type2(blob))
        if status == 0xC0000016:                       # MORE_PROCESSING_REQUIRED
            s.sendall(_netbios_wrap(
                _smb2_session_setup_pkt(sid, _ntlmssp_type3_pkt(), msgid=2)))
            resp = _recv_netbios_msg(s)
            if resp[:4] != b"\xfeSMB" or len(resp) < 68:
                info["error"] = "no SMB2 reply to session setup (NTLMSSP type 3)"
                return info
            status = int.from_bytes(resp[8:12], "little")
            sid = int.from_bytes(resp[40:48], "little")
        if status != 0:
            info["session_status"] = "0x%08x" % status
            return info
        info["smb2_session_setup"] = True
        info["session_id"] = "0x%016x" % sid
        msgid = 3
        for share in shares:
            s.sendall(_netbios_wrap(
                _smb2_tree_connect_pkt(sid, host, share, msgid)))
            msgid += 1
            r = _recv_netbios_msg(s)
            if r[:4] == b"\xfeSMB" and len(r) >= 68:
                st = int.from_bytes(r[8:12], "little")
                if st == 0:
                    info["smb2_anonymous_shares"].append(share)
                    info["smb2_share_types"][share] = {
                        1: "disk", 2: "printer", 3: "pipe",
                    }.get(r[66] if len(r) > 66 else 0, "unknown")
                else:
                    info["smb2_share_errors"][share] = "0x%08x" % st
            else:
                info["smb2_share_errors"][share] = "no reply"
    except (OSError, socket.timeout) as exc:
        info["error"] = "socket error: %s" % exc
    finally:
        try:
            s.close()
        except Exception:
            pass
    return info


def smb_enum(target_ip, port=445):
    """Probe SMB on a host: open shares, null-session access, dialects."""
    if not isinstance(target_ip, str) or not target_ip.strip():
        return _err("target_ip is required")
    host = target_ip.strip()
    try:
        p = int(port)
    except (TypeError, ValueError):
        p = 445
    result = {
        "target": host, "port": p, "smb_reachable": False, "dialects": [],
        "null_session": {}, "anonymous_shares": [], "notes": [],
    }
    resp = _tcp_banner(host, p, send=_netbios_wrap(_smb2_negotiate_pkt()),
                       read=4096)
    if not resp:
        result["notes"].append("no response on TCP %d" % p)
        return result
    result["smb_reachable"] = True
    resp = _netbios_unwrap(resp)
    if resp[:4] == b"\xfeSMB":
        neg = _smb2_parse_negotiate(resp)
        if not neg:
            result["notes"].append("SMB2 negotiate reply truncated")
        elif "status" in neg:
            result["notes"].append("SMB2 negotiate error 0x%08x" % neg["status"])
        else:
            result["protocol"] = "SMB2+"
            result["negotiated_dialect"] = neg["dialect"]
            result["signing_required"] = neg["signing_required"]
            result["server_guid"] = neg["server_guid"]
            result["dialects"].append(neg["dialect"])
            result["notes"].append("SMB2 negotiate succeeded (dialect %s)"
                                   % neg["dialect"])
            ns = _smb2_null_session_probe(
                host, p, ("IPC$", "NETLOGON", "SYSVOL", "ADMIN$", "C$"))
            for key in ("ntlm_server_challenge", "ntlm_target_name",
                        "ntlm_netbios_domain", "ntlm_netbios_computer",
                        "ntlm_dns_domain", "ntlm_dns_forest",
                        "ntlm_dns_computer"):
                if ns.get(key):
                    result["null_session"][key] = ns[key]
            result["null_session"]["smb2_session_setup"] = ns.get(
                "smb2_session_setup", False)
            if ns.get("smb2_session_setup"):
                result["anonymous_shares"] = list(dict.fromkeys(
                    result["anonymous_shares"] + ns["smb2_anonymous_shares"]))
                result["smb2_share_types"] = ns.get("smb2_share_types", {})
                result["notes"].append(
                    "SMB2 anonymous session accepted; accessible shares: %s"
                    % (", ".join(ns["smb2_anonymous_shares"]) or "none"))
            elif ns.get("session_status"):
                result["notes"].append("SMB2 anonymous session rejected (%s)"
                                       % ns["session_status"])
            if ns.get("smb2_share_errors"):
                result["smb2_share_errors"] = ns["smb2_share_errors"]
            if ns.get("error"):
                result["notes"].append("SMB2 null-session probe: %s" % ns["error"])
    elif resp[:4] == b"\xffSMB":
        result["protocol"] = "SMB1-only"
        result["notes"].append("server answered with SMB1 header")
    else:
        result["notes"].append("unexpected banner on SMB port")


    r1 = _tcp_banner(host, p, send=_netbios_wrap(_smb1_negotiate_pkt()),
                     read=4096)
    r1 = _netbios_unwrap(r1)
    if r1[:4] == b"\xffSMB" and len(r1) >= 36 and r1[4] == 0x72:
        body = r1[32:]
        if body and body[0] == 0:
            bc = int.from_bytes(body[1:3], "little")
            dialects = [int.from_bytes(body[3 + i:5 + i], "little")
                        for i in range(0, max(0, bc - 1), 2)]
            names = [_SMB1_DIALECTS.get(d, "0x%04x" % d) for d in dialects]
            result["smb1_enabled"] = True
            result["smb1_dialects"] = names
            result["dialects"] = list(dict.fromkeys(result["dialects"] + names))
            r2 = _tcp_banner(host, p, send=_netbios_wrap(_smb1_session_setup_pkt()),
                             read=4096)
            r2 = _netbios_unwrap(r2)
            if r2[:4] == b"\xffSMB":
                if r2[5] == 0 and r2[7:9] == b"\x00\x00":
                    result["null_session"]["smb1_session_setup"] = True
                    uid = int.from_bytes(r2[28:30], "little")
                    for share in ("IPC$", "NETLOGON", "SYSVOL", "ADMIN$", "C$"):
                        r3 = _tcp_banner(host, p,
                                         send=_netbios_wrap(
                                             _smb1_tree_connect_pkt(host, share)),
                                         read=4096)
                        if _smb1_response_ok(_netbios_unwrap(r3)):
                            result["anonymous_shares"].append(share)
                    result["null_session"]["smb1_tree_connect"] = (
                        len(result["anonymous_shares"]) > 0)
                    result["null_session"]["uid"] = uid
                else:
                    err = "0x%08x" % int.from_bytes(r2[5:9], "little")
                    result["null_session"]["smb1_session_setup"] = False
                    result["notes"].append("anonymous SMB1 session rejected (%s)" % err)
            else:
                result["notes"].append("SMB1 session setup produced no SMB reply")
        else:
            result["notes"].append("SMB1 negotiate replied with unexpected body")
    else:
        result["smb1_enabled"] = False
        result["smb1_dialects"] = []

    result["netbios_139"] = _tcp_open(host, 139)
    result["msrpc_135"] = _tcp_open(host, 135)

    result["anonymous_shares"] = list(dict.fromkeys(result["anonymous_shares"]))
    result["findings"] = []
    if result["null_session"].get("smb1_session_setup"):
        result["findings"].append({
            "severity": "high",
            "issue": "null session over SMB1 accepted - legacy anonymous access",
            "detail": "anonymous SMB1 session setup succeeded; shares opened: %s"
                      % (", ".join(result["anonymous_shares"]) or "IPC$"),
        })
    if result["null_session"].get("smb2_session_setup"):
        result["findings"].append({
            "severity": "high",
            "issue": "null session over SMB2 accepted - anonymous access",
            "detail": "anonymous SMB2 session setup succeeded; shares opened: %s"
                      % (", ".join(result["anonymous_shares"]) or "IPC$"),
        })
    if result.get("smb1_enabled"):
        result["findings"].append({
            "severity": "medium",
            "issue": "SMB1 enabled (protocol downgrade / legacy risk)",
            "detail": "server negotiates SMB1 dialects: %s" % ", ".join(
                result["smb1_dialects"] or []),
        })
    result["findings_count"] = len(result["findings"])
    return result


# --- Deep SMB share enumeration (anonymous session + TREE_CONNECT brute) ---
_SMB_SHARE_WORDLIST = (
    "IPC$", "ADMIN$", "C$", "D$", "E$", "F$", "NETLOGON", "SYSVOL",
    "Users", "Shared", "Shares", "Public", "Data", "Files", "FileStore",
    "Backup", "Backups", "Archive", "HR", "Finance", "IT", "Dev",
    "Development", "Deploy", "Release", "Source", "Code", "Projects",
    "Docs", "Documents", "Scans", "Print$", "Fax$", "Home", "Homes",
    "Profiles", "Roaming", "Software", "Apps", "Install", "Media",
    "Video", "Photos", "Music", "SQL", "Database", "Exchange", "WWW",
    "Web", "Inetpub", "Temp", "Tmp", "Transfer", "Drop", "Uploads",
    "Download", "Common", "Company", "Groups", "Department", "Secret",
    "Secure", "Restricted", "Management", "Admin", "Payroll",
    "Accounting", "Legal", "Contracts", "ISO", "Images", "VMs",
)


def _smb1_deep_share_scan(host, port, shares, timeout=DEFAULT_TIMEOUT):
    """SMB1 fallback: negotiate, anonymous session setup, then sequential
    TREE_CONNECTs to every candidate share on one connection."""
    out = {"accessible": [], "denied": {}, "session": False}
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_netbios_wrap(_smb1_negotiate_pkt()))
        if _netbios_unwrap(_recv_netbios_msg(s))[:4] != b"\xffSMB":
            out["error"] = "SMB1 negotiate failed"
            return out
        s.sendall(_netbios_wrap(_smb1_session_setup_pkt()))
        resp = _netbios_unwrap(_recv_netbios_msg(s))
        if resp[:4] != b"\xffSMB" or len(resp) < 36 or resp[4] != 0x73:
            out["error"] = "SMB1 session setup failed"
            return out
        if resp[5] == 0:
            uid = int.from_bytes(resp[28:30], "little")
            out["session"] = True
        else:
            out["error"] = "anonymous SMB1 session rejected (0x%08x)" % int.from_bytes(resp[5:9], "little")
            return out
        for share in shares:
            pkt = bytearray(_smb1_tree_connect_pkt(host, share))
            pkt[28:30] = uid.to_bytes(2, "little")
            s.sendall(_netbios_wrap(bytes(pkt)))
            r = _recv_netbios_msg(s)
            if _smb1_response_ok(r):
                out["accessible"].append(share)
            else:
                code = (int.from_bytes(r[5:9], "little")
                        if r[:4] == b"\xffSMB" and len(r) >= 9 else 0)
                out["denied"][share] = "0x%08x" % code
    except (OSError, socket.timeout) as exc:
        out["error"] = out.get("error") or "socket error: %s" % exc
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def smb_share_enum(target_ip, port=445, shares=""):
    """Deep anonymous SMB share enumeration: SMB2 NTLMSSP null session +
    TREE_CONNECT brute-force over a common-share wordlist, with an SMB1
    fallback path. Returns per-share access status and share types."""
    if not isinstance(target_ip, str) or not target_ip.strip():
        return _err("target_ip is required")
    host = target_ip.strip()
    try:
        p = int(port)
    except (TypeError, ValueError):
        p = 445
    if isinstance(shares, (list, tuple)):
        share_list = [str(x).strip() for x in shares if str(x).strip()]
    elif isinstance(shares, str) and shares.strip():
        share_list = [x.strip() for x in shares.replace(",", " ").split() if x.strip()]
    else:
        share_list = list(_SMB_SHARE_WORDLIST)
    result = {
        "target": host, "port": p, "shares_tested": len(share_list),
        "accessible": [], "share_types": {}, "errors": {}, "notes": [],
    }
    resp = _tcp_banner(host, p, send=_netbios_wrap(_smb2_negotiate_pkt()),
                       read=4096)
    sig = _netbios_unwrap(resp)[:4]
    if not resp:
        result["notes"].append("no response on TCP %d" % p)
        result["findings_count"] = 0
        return result
    result["protocol"] = "SMB2+" if sig == b"\xfeSMB" else ("SMB1" if sig == b"\xffSMB" else "unknown")
    if sig == b"\xfeSMB":
        ns = _smb2_null_session_probe(host, p, share_list)
        result["smb2_session_setup"] = ns.get("smb2_session_setup", False)
        for k in ("ntlm_target_name", "ntlm_netbios_domain", "ntlm_dns_domain"):
            if ns.get(k):
                result[k] = ns[k]
        if ns.get("smb2_session_setup"):
            result["accessible"] = ns["smb2_anonymous_shares"]
            result["share_types"] = ns.get("smb2_share_types", {})
            result["errors"] = ns.get("smb2_share_errors", {})
        else:
            result["notes"].append(
                "anonymous SMB2 session rejected (%s); trying SMB1 fallback"
                % ns.get("session_status", "no session"))
            s1 = _smb1_deep_share_scan(host, p, share_list)
            result["smb1_fallback"] = True
            result["accessible"] = s1["accessible"]
            result["errors"] = s1["denied"]
            if s1.get("error"):
                result["notes"].append("SMB1 fallback: %s" % s1["error"])
    else:
        s1 = _smb1_deep_share_scan(host, p, share_list)
        result["smb1_fallback"] = True
        result["accessible"] = s1["accessible"]
        result["errors"] = s1["denied"]
        if s1.get("error"):
            result["notes"].append("SMB1 scan: %s" % s1["error"])
    result["accessible_count"] = len(result["accessible"])
    result["findings"] = []
    if result["accessible"]:
        admin = [sh for sh in result["accessible"]
                 if sh.upper() in ("ADMIN$", "C$", "D$", "E$")]
        if admin:
            result["findings"].append({
                "severity": "critical",
                "issue": "administrative share accessible without credentials",
                "detail": "anonymous TREE_CONNECT succeeded on %s" % ", ".join(admin),
            })
        result["findings"].append({
            "severity": "high",
            "issue": "anonymous share enumeration succeeded",
            "detail": "accessible shares: %s" % ", ".join(result["accessible"]),
        })
    result["findings_count"] = len(result["findings"])
    return result


# Anonymous LDAP enumeration
def _ldap_bind_anonymous(msgid):
    bind = _ber_ctx(0, _ber_seq(_ber_int(3), _ber_octets(b""), _tlv(0x80, b"")))
    return _ldap_msg(msgid, bind)


def _ldap_paged_control(size, cookie=b""):
    """MS paged-results control (1.2.840.113556.1.4.319)."""
    value = _ber_seq(_ber_int(size), _ber_octets(cookie))
    return _ber_seq(_ber_octets("1.2.840.113556.1.4.319"), _ber_bool(False),
                    _ber_octets(bytes(value)))


def _ldap_search_req(msgid, base, attrs, scope=2, controls=None):
    filt = _tlv(0x87, b"")                            # present: objectClass
    parts = [
        _ber_octets(base),
        _ber_enum(scope),
        _ber_enum(0),
        _ber_int(0),
        _ber_int(0),
        _ber_bool(False),
        filt,
        _ber_seq(*[_ber_octets(a) for a in attrs]),
    ]
    if controls:
        parts.append(_tlv(0xA0, b"".join(controls)))  # controls [0]
    req = _ber_seq(*parts)
    return _ldap_msg(msgid, _ber_ctx(3, req))


def _ldap_parse_msgs(data):
    msgs, off = [], 0
    while off < len(data):
        try:
            tag, payload, off = _ber_read(data, off)
        except Exception:
            break
        if tag != 0x30:
            break
        msgid, app_tag, app = 0, None, None
        try:
            for t, pl in _ber_iter(payload):
                if t == 0x02:
                    msgid = int.from_bytes(pl, "big", signed=False)
                elif t & 0x60 == 0x60:
                    app_tag, app = t, pl
        except Exception:
            continue
        if app is None:
            continue
        m = {"message_id": msgid}
        if app_tag == 0x61:                           # BindResponse
            try:
                code = dict(_ber_iter(app)).get(0x0A)
            except Exception:
                code = None
            m["type"] = "bind_response"
            m["result_code"] = int.from_bytes(code, "big") if code else None
        elif app_tag == 0x64:                         # SearchResultEntry
            entry = {"dn": ""}
            attrs = {}
            try:
                for t, pl in _ber_iter(app):
                    if t == 0x04:
                        entry["dn"] = pl.decode("utf-8", "replace")
                    elif t == 0x30:
                        for at, apl in _ber_iter(pl):
                            inner = dict(_ber_iter(apl))
                            aname = inner.get(0x04)
                            avals = []
                            for vt, vpl in _ber_iter(inner.get(0x30, b"")):
                                if vt == 0x04:
                                    avals.append(vpl.decode("utf-8", "replace"))
                            if aname is not None:
                                attrs[aname.decode("utf-8", "replace")] = avals
            except Exception:
                pass
            entry["attributes"] = attrs
            m["type"] = "search_entry"
            m.update(entry)
        elif app_tag == 0x65:                         # SearchResultDone
            try:
                code = dict(_ber_iter(app)).get(0x0A)
            except Exception:
                code = None
            m["type"] = "search_done"
            m["result_code"] = int.from_bytes(code, "big") if code else None
            m["paged_cookie"] = _ldap_paged_cookie(app)
        elif app_tag == 0x73:                         # SearchResultReference
            refs = []
            for t, pl in _ber_iter(app):
                if t == 0x04:
                    refs.append(pl.decode("utf-8", "replace"))
            m["type"] = "search_reference"
            m["referrals"] = refs
        msgs.append(m)
    return msgs


def _ldap_paged_cookie(done_payload):
    """Extract the paged-results cookie from SearchResultDone controls."""
    try:
        for t, pl in _ber_iter(done_payload):
            if t != 0xA0:                              # controls [0]
                continue
            for ct, cv in _ber_iter(pl):
                if ct != 0x30:                         # control SEQUENCE
                    continue
                oid, value = None, None
                for kt, kv in _ber_iter(cv):
                    if kt == 0x04:
                        if oid is None:
                            oid = kv
                        else:
                            value = kv
                if oid == b"1.2.840.113556.1.4.319" and value:
                    # controlValue wraps SEQUENCE {size, cookie}
                    try:
                        st, seq_pl, _ = _ber_read(value, 0)
                        if st == 0x30:
                            value = seq_pl
                    except Exception:
                        pass
                    for st, sp in _ber_iter(value):
                        if st == 0x04:
                            return sp
    except Exception:
        pass
    return b""


_LDAP_ERRORS = {
    0: "success", 1: "operationsError", 2: "protocolError", 3: "timeLimitExceeded",
    4: "sizeLimitExceeded", 10: "referral", 11: "adminLimitExceeded",
    13: "confidentialityRequired", 32: "noSuchObject", 34: "invalidDNSyntax",
    48: "inappropriateAuthentication", 49: "invalidCredentials",
    50: "insufficientAccessRights", 51: "busy", 52: "unavailable",
    53: "unwillingToPerform", 80: "other",
}
_ROOT_DSE_ATTRS = [
    "namingContexts", "defaultNamingContext", "rootDomainNamingContext",
    "supportedLDAPVersion", "supportedSASLMechanisms", "dnsHostName",
    "serverName", "subschemaSubentry", "vendorName", "domainFunctionality",
    "forestFunctionality", "supportedCapabilities",
]


def ldap_search_anonymous(target_ip, base_dn=""):
    """Anonymous LDAP bind + search against root DSE or a supplied base DN."""
    if not isinstance(target_ip, str) or not target_ip.strip():
        return _err("target_ip is required")
    host = target_ip.strip()
    base = (base_dn or "").strip()
    result = {
        "target": host, "port": 389, "anonymous_bind": False,
        "naming_contexts": [], "entries": [], "referrals": [],
        "attributes": {}, "errors": [],
    }
    try:
        s = socket.create_connection((host, 389), timeout=DEFAULT_TIMEOUT)
    except OSError as exc:
        result["errors"].append("connection failed: %s" % exc)
        return result
    try:
        s.settimeout(DEFAULT_TIMEOUT)
        s.sendall(_ldap_bind_anonymous(1))
        try:
            buf = s.recv(8192)
        except socket.timeout:
            buf = b""
            result["errors"].append("no bind response (LDAP may require TLS/port 636)")
        bind_code = None
        for m in _ldap_parse_msgs(buf):
            if m.get("type") == "bind_response":
                bind_code = m.get("result_code")
                break
        if bind_code == 0:
            result["anonymous_bind"] = True
        elif bind_code is not None:
            result["errors"].append(
                "anonymous bind refused: %s" % _LDAP_ERRORS.get(bind_code, bind_code))
        else:
            result["errors"].append("could not parse LDAP bind response")

        if result["anonymous_bind"]:
            scope = 0 if not base else 2
            msgid = 2
            cookie = b""
            pages = 0
            result["paged_search"] = bool(base)
            while True:
                s.sendall(_ldap_search_req(
                    msgid, base, _ROOT_DSE_ATTRS, scope=scope,
                    controls=[_ldap_paged_control(1000, cookie)] if base else None))
                buf = b""
                try:
                    while True:
                        chunk = s.recv(8192)
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) > 512 * 1024:
                            break
                except socket.timeout:
                    pass
                done = False
                for m in _ldap_parse_msgs(buf):
                    if m.get("type") == "search_entry":
                        attrs = m.get("attributes", {})
                        if len(result["entries"]) < 2000:
                            result["entries"].append({"dn": m.get("dn", ""),
                                                      "attributes": attrs})
                        for k, v in attrs.items():
                            result["attributes"].setdefault(k, [])
                            for item in v:
                                if item not in result["attributes"][k]:
                                    result["attributes"][k].append(item)
                    elif m.get("type") == "search_reference":
                        result["referrals"].extend(m.get("referrals", []))
                    elif m.get("type") == "search_done":
                        code = m.get("result_code")
                        if code not in (0, None):
                            result["errors"].append(
                                "search failed: %s" % _LDAP_ERRORS.get(code, code))
                        done = True
                        cookie = m.get("paged_cookie") or b""
                pages += 1
                if not base or not done or not cookie or pages >= 25:
                    break
                msgid += 1
            result["pages_received"] = pages
            result["entry_count"] = len(result["entries"])
            result["naming_contexts"] = result["attributes"].get("namingContexts", [])
            result["default_naming_context"] = (
                result["attributes"].get("defaultNamingContext", [""])[0] or None)
            result["root_domain_naming_context"] = (
                result["attributes"].get("rootDomainNamingContext", [""])[0] or None)
            result["supported_ldap_versions"] = result["attributes"].get(
                "supportedLDAPVersion", [])
            result["supported_sasl"] = result["attributes"].get(
                "supportedSASLMechanisms", [])
            result["server_dns_host"] = (
                result["attributes"].get("dnsHostName", [""])[0] or None)
            result["entry_count"] = len(result["entries"])
    except OSError as exc:
        result["errors"].append("socket error: %s" % exc)
    finally:
        try:
            s.close()
        except Exception:
            pass
    result["findings"] = []
    if result["naming_contexts"]:
        result["findings"].append({
            "severity": "medium",
            "issue": "anonymous LDAP bind + enumeration permitted",
            "detail": "naming contexts exposed: %s" % ", ".join(
                result["naming_contexts"]),
        })
    if not result["entries"] and result["anonymous_bind"] and not base:
        result["errors"].append(
            "root DSE search returned no entries (server may restrict anonymous queries)")
    result["findings_count"] = len(result["findings"])
    return result


# Kerberos AS-REQ probing / AS-REP roasting detection
_KRB_ERRORS = {
    1: "KDC_ERR_NAME_EXPIRED", 2: "KDC_ERR_SERVICE_EXPIRED",
    3: "KDC_ERR_BAD_PVNO", 4: "KDC_ERR_C_OLD_MAST_KVNO",
    5: "KDC_ERR_C_PRINCIPAL_UNKNOWN", 6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
    9: "KDC_ERR_NULL_KEY", 10: "KDC_ERR_CANNOT_POSTDATE",
    21: "KDC_ERR_PREAUTH_REQUIRED", 22: "KDC_ERR_PREAUTH_FAILED",
    23: "KDC_ERR_PREAUTH_FAILED", 24: "KDC_ERR_KEY_EXPIRED",
    25: "KDC_ERR_PREAUTH_REQUIRED", 31: "KDC_ERR_MUST_USE_USER2USER",
    37: "KDC_ERR_KDC_NOT_TRUSTED", 41: "KDC_ERR_POLICY",
    52: "KDC_ERR_GENERIC", 56: "KDC_ERR_ETYPE_NOSUPP",
    60: "KDC_ERR_PREAUTH_EXPIRED", 61: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
}
_ETYPES = (18, 17, 23, 16, 3, 1)  # AES256, AES128, RC4-HMAC, 3DES, DES


def _as_req_body(username, realm):
    now = datetime.datetime.utcnow()
    till = now + datetime.timedelta(days=1)
    options = _tlv(0x80, b"\x41\x00\x00\x02\x00")
    cname = _ber_seq(
        _ber_ctx(0, _ber_int(1), constructed=False),
        _ber_ctx(1, _ber_seq(_tlv(0x1C, username.encode()))),
    )
    sname = _ber_seq(
        _ber_ctx(0, _ber_int(2), constructed=False),
        _ber_ctx(1, _ber_seq(_tlv(0x1C, b"krbtgt"),
                             _tlv(0x1C, realm.encode()))),
    )
    body = _ber_seq(
        _ber_ctx(0, options),
        _ber_ctx(1, cname),
        _ber_ctx(2, _tlv(0x1C, realm.encode())),
        _ber_ctx(3, sname),
        _ber_ctx(5, _tlv(0x18, till.strftime("%Y%m%d%H%M%SZ").encode())),
        _ber_ctx(7, _ber_int(random.getrandbits(32))),
        _ber_ctx(8, _ber_seq(*[_ber_int(e) for e in _ETYPES])),
    )
    return body


def _as_req_pkt(username, realm):
    body = _as_req_body(username, realm)
    req = _ber_seq(
        _ber_ctx(1, _ber_int(5)),
        _ber_ctx(2, _ber_int(10)),
        _ber_ctx(4, body),
    )
    return _tlv(0x6A, req)  # [APPLICATION 10] KRB_AS_REQ


def _parse_kdc_response(resp):
    if not resp:
        return {"reply": False}
    tag = resp[0]
    if tag == 0x6B:
        return {"reply": True, "kind": "AS-REP", "asrep": True}
    if tag == 0x7E:  # KRB-ERROR
        err_code, e_text = None, ""
        try:
            _, payload, _ = _ber_read(resp, 0)
            for t, pl in _ber_iter(payload):
                if t == 0xA7:  # error-code [7]
                    err_code = int.from_bytes(pl, "big", signed=False)
                elif t == 0xA8:  # e-text [8]
                    e_text = pl.decode("utf-8", "replace")
        except Exception:
            pass
        name = _KRB_ERRORS.get(err_code, "KRB error %s" % err_code)
        return {"reply": True, "kind": "KRB-ERROR", "error_code": err_code,
                "error_name": name, "e_text": e_text}
    return {"reply": True, "kind": "unknown", "first_byte": hex(tag)}


def kerberos_ticket_check(target_ip, domain, usernames="Administrator"):
    """Probe KDC on port 88 with raw AS-REQs to fingerprint responses and
    detect AS-REP (pre-auth disabled) roastable accounts."""
    if not isinstance(target_ip, str) or not target_ip.strip():
        return _err("target_ip is required")
    host = target_ip.strip()
    realm = (domain or "").strip().upper()
    result = {
        "target": host, "port": 88, "kdc_reachable": False,
        "realm_checked": realm or None, "users": [],
        "asrep_roastable": [], "notes": [],
    }
    if not realm:
        result["notes"].append("no realm supplied; probing with KDC-ERROR analysis only")
        realm = "PROBE"
    names = [u.strip() for u in (usernames or "Administrator").split(",") if u.strip()]
    names = names or ["Administrator"]
    for user in names:
        r = _tcp_banner(host, 88, send=_as_req_pkt(user, realm), read=65536)
        parsed = _parse_kdc_response(r)
        if not parsed.get("reply"):
            result["notes"].append("no KDC response for '%s' (filtered/closed?)" % user)
            continue
        result["kdc_reachable"] = True
        entry = {"username": user}
        if parsed.get("kind") == "AS-REP":
            entry["status"] = "AS-REP received (pre-auth disabled)"
            entry["asrep_roastable"] = True
            entry["severity"] = "critical"
            result["asrep_roastable"].append(user)
        elif parsed.get("kind") == "KRB-ERROR":
            entry["error_code"] = parsed.get("error_code")
            entry["error_name"] = parsed.get("error_name")
            if parsed.get("error_code") == 25:      # PREAUTH_REQUIRED
                entry["status"] = "account exists, pre-auth required (not roastable)"
                entry["asrep_roastable"] = False
            elif parsed.get("error_code") == 6:     # C_PRINCIPAL_UNKNOWN
                entry["status"] = "account not found"
                entry["asrep_roastable"] = False
            else:
                entry["status"] = "KDC responded with %s" % parsed.get("error_name")
                entry["asrep_roastable"] = False
        else:
            entry["status"] = "unexpected KDC reply type"
            entry["asrep_roastable"] = False
        result["users"].append(entry)

    result["findings"] = []
    if result["asrep_roastable"]:
        result["findings"].append({
            "severity": "critical",
            "issue": "AS-REP roastable account(s) - Kerberos pre-authentication disabled",
            "detail": "accounts: %s - request AS-REP and crack the encrypted TGT "
                      "offline (hashcat mode 18200 / john krb5asrep)" % ", ".join(
                          result["asrep_roastable"]),
        })
    elif result["kdc_reachable"]:
        result["findings"].append({
            "severity": "info",
            "issue": "KDC reachable and responding to AS-REQ probes",
            "detail": "port 88 responds; user enumeration responses recorded per user",
        })
    result["findings_count"] = len(result["findings"])
    return result


# Internal subnet sweep
def _probe_host(host, ports, timeout):
    open_ports = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                open_ports.append(p)
        except (OSError, socket.timeout):
            continue
    return {"host": host, "open_ports": open_ports,
            "alive": bool(open_ports)}


def subnet_sweep(subnet_cidr, ports=None,
                 max_hosts=_MAX_SWEEP_HOSTS, workers=200, timeout=1.5):
    """Rapid parallel TCP host discovery across an internal CIDR block."""
    if not isinstance(subnet_cidr, str) or not subnet_cidr.strip():
        return _err("subnet_cidr is required (e.g. 10.10.10.0/24)")
    try:
        net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
    except ValueError as exc:
        return _err("invalid subnet_cidr: %s" % exc)
    if net.version != 4:
        return _err("only IPv4 CIDR blocks are supported")
    port_list = [int(x) for x in (ports or [80, 445, 3389, 22])]
    port_list = [p for p in port_list if 0 < p < 65536] or [80, 445, 3389, 22]
    try:
        mh = int(max_hosts) or _MAX_SWEEP_HOSTS
        wk = max(1, min(int(workers) or 200, 500))
        to = min(float(timeout) or 1.5, 10.0)
    except (TypeError, ValueError):
        mh, wk, to = _MAX_SWEEP_HOSTS, 200, 1.5

    result = {
        "subnet": str(net), "total_hosts": net.num_addresses,
        "max_hosts_cap": mh, "scanned_hosts": 0, "alive_hosts": [],
        "open_ports_seen": sorted(port_list), "errors": [],
    }
    if net.num_addresses > mh:
        result["errors"].append(
            "subnet has %d addresses which exceeds the %d host cap; "
            "narrow the CIDR (e.g. /%d)" % (net.num_addresses, mh,
                                            max(8, 32 - (mh.bit_length() - 1))))
        return result
    hosts = [str(h) for h in net.hosts()]
    started = time.time()
    with ThreadPoolExecutor(max_workers=wk) as pool:
        futs = [pool.submit(_probe_host, h, port_list, to) for h in hosts]
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception as exc:
                result["errors"].append("worker error: %s" % exc)
                continue
            result["scanned_hosts"] += 1
            if r["alive"]:
                result["alive_hosts"].append(r)
    result["alive_count"] = len(result["alive_hosts"])
    result["duration_seconds"] = round(time.time() - started, 2)
    result["findings"] = []
    for h in result["alive_hosts"]:
        if 445 in h["open_ports"]:
            result["findings"].append({
                "severity": "info",
                "issue": "SMB service exposed",
                "host": h["host"], "detail": "port 445 open (AD file sharing)",
            })
    result["findings_count"] = len(result["findings"])
    return result
