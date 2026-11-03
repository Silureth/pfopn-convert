#!/usr/bin/env python3
"""Sanitize pfSense/OPNsense config.xml backups so they can be shared as test data.

What it replaces (structure and formatting are preserved; the same input value
always maps to the same replacement within one run, so cross-references still
line up):

  * secrets: passwords/hashes, certificate and private keys, CSRs, OpenVPN/
    IPsec/WireGuard keys, PSKs, SNMP communities, API keys/tokens, OTP seeds,
    SSH authorized keys, and any leaf element whose tag name looks secret
  * public IPv4 addresses  -> 198.18.0.0/15 (one /24 per source /24, last octet kept)
  * global IPv6 addresses  -> 2001:db8:N::/48 (one /48 per source /48, low bits kept)
  * domains from <system><domain> and any --term words (case-insensitive)
  * e-mail addresses

It never prints original values. The report lists tag names and counts only,
then cross-checks that no redacted value, public IP, domain or term survives
anywhere in the output.

Usage:
  sanitize_config.py --out-dir OUT [--term WORD ...] [--salt-file F] IN.xml [IN.xml ...]
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sys

# Leaf elements that are always secret (or identifying key material).
STRONG_TAGS = {
    "password", "bcrypt-hash", "sha512-hash", "md5-hash", "nt-hash", "lm-hash",
    "prv", "crt", "csr", "authorizedkeys",
    "shared_key", "tls", "tls_key", "tlskey", "static_key",
    "pre-shared-key", "ipsecpsk", "psk", "presharedkey", "pskey",
    "privatekey", "privkey", "publickey", "pubkey",
    "rocommunity", "rwcommunity", "community",
    "radius_secret", "radius_secret2", "ldap_bindpw", "bindpw",
    "passphrase", "wpa_passphrase", "otp_seed", "secret", "apikey", "apisecret",
    "auth_pass", "auth_user_pass", "authkey", "auth_key", "preauthkey",
    "ddnsdomainkey", "tsig_secret", "md5sigkey", "md5password",
    "accountkey", "oinkcode", "maxmind_account", "tlspskfile",
}

# Base64 text blobs that are redacted wholesale (package free-text that may hold
# credentials, DHCP lease backups). Other base64 text blobs are decoded,
# anonymized (IPs, domains, e-mails) and re-encoded.
BLOB_REDACT_TAGS = {"data", "advanced", "advanced_backend", "userparams", "content"}

# Tag names that look secret. Redacted unless the value is empty/boolean/numeric.
WEAK_TAG_RE = re.compile(
    r"(passw|passphrase|secret|psk|private|privkey|token|community|hash|seed|"
    r"apikey|api_key|authkey|auth_key|preauth|sharedkey|shared_key|bindpw|"
    r"credential|_key$|^key$|^keys$)",
    re.IGNORECASE,
)
# Structural tags that match WEAK_TAG_RE but hold settings, not secrets.
WEAK_EXCLUDE_RE = re.compile(
    r"(keylen|keytype|key_type|key_len|keyexchange|key_exchange|keysize|"
    r"lifetime|_mode$|_type$|_len$|length$|enabled?$|hash_algo|hashalgo|"
    r"digest_alg|privacy|private_networks|privateaddress|blockpriv|"
    r"hash-algorithm|keydir|stickiness|log_files_hash|redis_key)",
    re.IGNORECASE,
)
NON_SECRET_VALUE_RE = re.compile(r"^(|yes|no|on|off|true|false|enabled|disabled|\d{1,6})$", re.IGNORECASE)

LEAF_RE = re.compile(
    r"<(?P<tag>[A-Za-z_][\w.\-:]*)(?P<attrs>\s[^<>]*?)?>"
    r"(?P<val><!\[CDATA\[.*?\]\]>|[^<]*)"
    r"</(?P=tag)>",
    re.DOTALL,
)
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])([23][0-9A-Fa-f]{3}:[0-9A-Fa-f:]*[0-9A-Fa-f])(?![0-9A-Fa-f:])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}(?![\w.])")
B64_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

KEEP_PUBLIC_V4 = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
}
BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def decode_text_blob(value: str) -> str | None:
    """Return decoded text if value is a base64-encoded UTF-8 text blob, else None."""
    v = re.sub(r"\s+", "", value)
    if len(v) < 24 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v) or len(v) % 4:
        return None
    try:
        raw = base64.b64decode(v, validate=True)
        text = raw.decode("utf-8")
    except Exception:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if text and printable / len(text) > 0.95 else None


class Sanitizer:
    def __init__(self, salt: bytes, terms: list[str]):
        self.salt = salt
        self.terms = sorted({t for t in terms if t}, key=len, reverse=True)
        self.term_map: dict[str, str] = {}
        self.v4_net_map: dict[str, int] = {}
        self.v6_net_map: dict[int, int] = {}
        self.email_map: dict[str, str] = {}
        self.redacted_values: dict[str, str] = {}
        self.public_v4_seen: set[str] = set()
        self.stats: dict[str, collections.Counter] = {}

    # -- deterministic pseudo-random material -----------------------------
    def _stream(self, label: str, value: str, n: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < n:
            out += hmac.new(self.salt, f"{label}|{counter}|{value}".encode(), hashlib.sha256).digest()
            counter += 1
        return out[:n]

    def _hex(self, label: str, value: str, n: int) -> str:
        return self._stream(label, value, (n + 1) // 2).hex()[:n]

    # -- secret replacement ------------------------------------------------
    def fake_secret(self, tag: str, value: str) -> str:
        v = value.strip()
        if v.startswith("$2"):  # bcrypt
            raw = self._stream("bcrypt", v, 53)
            return "$2y$10$" + "".join(BCRYPT_ALPHABET[b % 64] for b in raw)
        if re.match(r"^\$[156]\$", v):  # md5/sha256/sha512 crypt
            prefix = v[:3]
            raw = self._stream("crypt", v, 86)
            return prefix + "".join(BCRYPT_ALPHABET[b % 64] for b in raw[:8]) + "$" + "".join(
                BCRYPT_ALPHABET[b % 64] for b in raw[8:])
        if len(v) >= 16 and HEX_RE.match(v):
            return self._hex("hex", v, len(v))
        if len(v) >= 16 and B64_RE.match(v):
            compact = re.sub(r"\s+", "", v)
            try:
                n = len(base64.b64decode(compact, validate=False))
            except Exception:
                n = len(compact) * 3 // 4
            n = max(n, 1)
            return base64.b64encode(self._stream("b64", compact, n)).decode()
        return "REDACTED_" + self._hex("txt", v, 10)

    def classify(self, tag: str, value: str) -> str | None:
        """Return 'strong'/'weak' if the leaf must be redacted, else None."""
        t = tag.lower()
        if t in STRONG_TAGS:
            return "strong" if value.strip() else None
        if WEAK_TAG_RE.search(t) and not WEAK_EXCLUDE_RE.search(t):
            if NON_SECRET_VALUE_RE.match(value.strip()):
                return None
            return "weak"
        return None

    def redact_leaves(self, text: str, st: collections.Counter) -> str:
        def repl(m: re.Match) -> str:
            tag, attrs, val = m.group("tag"), m.group("attrs") or "", m.group("val")
            cdata = val.startswith("<![CDATA[")
            inner = val[9:-3] if cdata else val
            kind = self.classify(tag, inner)
            blob = decode_text_blob(inner) if kind is None else None
            is_b64 = len(inner.strip()) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", inner.strip()) is not None
            if kind is None and is_b64 and tag.lower() in BLOB_REDACT_TAGS:
                blob = ""  # binary or text: redact either way
            if blob is not None:
                if tag.lower() in BLOB_REDACT_TAGS:
                    st[f"redact:blob:{tag}"] += 1
                    fake = base64.b64encode(f"REDACTED_{self._hex('blob', inner, 10)}\n".encode()).decode()
                else:
                    st[f"blob-sanitized:{tag}"] += 1
                    fake = base64.b64encode(self.sanitize_text(blob, st).encode()).decode()
                new_val = f"<![CDATA[{fake}]]>" if cdata else fake
                return f"<{tag}{attrs}>{new_val}</{tag}>"
            if kind is None:
                return m.group(0)
            st[f"redact:{kind}:{tag}"] += 1
            if len(inner.strip()) >= 4:
                self.redacted_values.setdefault(inner.strip(), f"secret<{tag}>")
            fake = self.fake_secret(tag, inner)
            new_val = f"<![CDATA[{fake}]]>" if cdata else fake
            return f"<{tag}{attrs}>{new_val}</{tag}>"

        return LEAF_RE.sub(repl, text)

    # -- network/identity anonymization -----------------------------------
    def map_v4(self, text: str, st: collections.Counter) -> str:
        def repl(m: re.Match) -> str:
            s = m.group(1)
            try:
                ip = ipaddress.IPv4Address(s)
            except ValueError:
                return s
            if not ip.is_global or s in KEEP_PUBLIC_V4 or ip.is_multicast:
                return s
            self.public_v4_seen.add(s)
            net = ".".join(s.split(".")[:3])
            if net not in self.v4_net_map:
                self.v4_net_map[net] = len(self.v4_net_map)
            idx = self.v4_net_map[net]
            if idx >= 512:
                raise SystemExit("too many public /24 networks to map into 198.18.0.0/15")
            st["ipv4:public"] += 1
            return f"198.{18 + idx // 256}.{idx % 256}.{s.split('.')[3]}"

        return IPV4_RE.sub(repl, text)

    def map_v6(self, text: str, st: collections.Counter) -> str:
        def repl(m: re.Match) -> str:
            s = m.group(1)
            try:
                ip = ipaddress.IPv6Address(s)
            except ValueError:
                st["ipv6:unparsed"] += 1
                return s
            if not ip.is_global or ip in ipaddress.IPv6Network("2001:db8::/32"):
                return s
            self.public_v4_seen.add(s.lower())
            n = int(ip)
            net48 = n >> 80
            if net48 not in self.v6_net_map:
                self.v6_net_map[net48] = len(self.v6_net_map) + 1
            new = (0x20010DB8 << 96) | (self.v6_net_map[net48] << 80) | (n & ((1 << 80) - 1))
            st["ipv6:global"] += 1
            return str(ipaddress.IPv6Address(new))

        return IPV6_RE.sub(repl, text)

    def map_terms(self, text: str, st: collections.Counter) -> str:
        for i, term in enumerate(self.terms):
            if term.lower() not in self.term_map:
                self.term_map[term.lower()] = (
                    f"site{len(self.term_map) + 1}.example" if "." in term else f"org{len(self.term_map) + 1}"
                )
            pat = re.compile(re.escape(term), re.IGNORECASE)
            text, n = pat.subn(self.term_map[term.lower()], text)
            if n:
                st[f"term#{i + 1}"] += n
        return text

    def map_emails(self, text: str, st: collections.Counter) -> str:
        def repl(m: re.Match) -> str:
            e = m.group(0).lower()
            if e.endswith("@example.net"):
                return m.group(0)
            if e not in self.email_map:
                self.email_map[e] = f"user{len(self.email_map) + 1}@example.net"
            st["email"] += 1
            return self.email_map[e]

        return EMAIL_RE.sub(repl, text)

    def sanitize_text(self, text: str, st: collections.Counter) -> str:
        text = self.map_emails(text, st)
        text = self.map_terms(text, st)
        text = self.map_v6(text, st)
        return self.map_v4(text, st)

    def sanitize(self, name: str, text: str) -> str:
        st = self.stats.setdefault(name, collections.Counter())
        text = self.redact_leaves(text, st)
        text = self.map_emails(text, st)
        text = self.map_terms(text, st)
        text = self.map_v6(text, st)
        text = self.map_v4(text, st)
        return text


def collect_domains(text: str) -> list[str]:
    m = re.search(r"<system>.*?</system>", text, re.DOTALL)
    if not m:
        return []
    return [d.strip() for d in re.findall(r"<domain>([^<]+)</domain>", m.group(0)) if d.strip()]


def load_salt(path: str | None) -> bytes:
    if not path:
        return secrets.token_bytes(32)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()
    salt = secrets.token_bytes(32)
    with open(path, "wb") as fh:
        fh.write(salt)
    os.chmod(path, 0o600)
    return salt


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--term", action="append", default=[], help="extra word to anonymize (org/site names)")
    ap.add_argument("--salt-file", help="persist the HMAC salt so later runs map values identically")
    args = ap.parse_args()

    texts: dict[str, str] = {}
    for path in args.inputs:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read()
        if "<?xml" not in text[:200] and not text.lstrip().startswith("<"):
            print(f"SKIP {os.path.basename(path)}: not an XML config", file=sys.stderr)
            continue
        texts[path] = text

    terms = list(args.term)
    for text in texts.values():
        terms.extend(collect_domains(text))
    san = Sanitizer(load_salt(args.salt_file), terms)

    os.makedirs(args.out_dir, exist_ok=True)
    outputs: dict[str, str] = {}
    for path, text in texts.items():
        base = os.path.basename(path)
        out_name = san.map_terms(base, collections.Counter())
        out_text = san.sanitize(out_name, text)
        out_path = os.path.join(args.out_dir, out_name)
        with open(out_path, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(out_text)
        os.chmod(out_path, 0o600)
        outputs[out_path] = out_text

    # Report (tag names and counts only, never values).
    for name, st in san.stats.items():
        print(f"== {name}")
        redact = collections.Counter({k.split(":", 2)[2] + (" (heuristic)" if ":weak:" in k else ""): v
                                      for k, v in st.items() if k.startswith("redact:") and ":blob:" not in k})
        redact.update({k.split(":", 2)[2] + " (blob)": v for k, v in st.items() if k.startswith("redact:blob:")})
        print("   redacted:", ", ".join(f"{k}={v}" for k, v in sorted(redact.items())) or "-")
        other = {k: v for k, v in st.items() if not k.startswith("redact:")}
        print("   mapped:  ", ", ".join(f"{k}={v}" for k, v in sorted(other.items())) or "-")

    # Leak check: no redacted value, public IP or term may survive anywhere.
    # Well-known defaults (e.g. SNMP "public") also occur as ordinary words; not leaks.
    defaults = {"public", "private", "pfsense", "opnsense"}
    needles: dict[str, str] = {
        v: c for v, c in san.redacted_values.items() if len(v) >= 6 and v.lower() not in defaults
    }
    needles.update({ip: "public-ip" for ip in san.public_v4_seen})
    needles.update({t.lower(): "term" for t in san.terms if len(t) >= 4})
    needles.update({e: "email" for e in san.email_map})
    leaks = 0
    for out_path, out_text in outputs.items():
        blobs = [b for b in (decode_text_blob(v) for v in re.findall(r">([A-Za-z0-9+/=\s]{24,})<", out_text)) if b]
        out_text = out_text + "\n<decoded-blobs>" + "\n".join(blobs)
        low = out_text.lower()
        for needle, cat in needles.items():
            pos = low.find(needle.lower())
            while pos != -1:
                leaks += 1
                opens = re.findall(r"<([A-Za-z_][\w.\-:]*)[^<>]*>", out_text[max(0, pos - 2000):pos])
                where = opens[-1] if opens else "?"
                print(f"!! {os.path.basename(out_path)}: {cat} found inside <{where}>", file=sys.stderr)
                pos = low.find(needle.lower(), pos + 1)
    print(f"leak check: {'FAILED' if leaks else 'ok'} ({len(needles)} distinct values checked)")
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
