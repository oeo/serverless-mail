import base64
import json
import logging
import os
import re
import secrets
import time
from functools import lru_cache
from urllib.parse import unquote_to_bytes
from email import policy
from email.header import Header, decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from email.utils import formataddr, getaddresses

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
ses = boto3.client("sesv2", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
table = boto3.resource("dynamodb").Table(os.environ["TABLE"])

BUCKET = os.environ["BUCKET"]
PREFIX = os.environ.get("PREFIX", "raw/")
DOMAIN = os.environ["DOMAIN"].strip().lower()
ALIASES = [a.strip().lower() for a in os.environ["ALIASES"].split(",") if a.strip()]
ALIAS_NAME = os.environ.get("ALIAS_NAME", "")
PRIVATE = os.environ["PRIVATE"].strip()
PRIVATE_DOMAIN = PRIVATE.rsplit("@", 1)[1].lower()
PRIVATE = PRIVATE.rsplit("@", 1)[0] + "@" + PRIVATE_DOMAIN
MAX_BYTES = int(os.environ.get("MAX_BYTES", 38 * 1024 * 1024))
OUTBOUND = os.environ.get("OUTBOUND", "false").lower() == "true"
REF_DOMAIN = "ref." + DOMAIN
DAY = 86400

ADDR_SPEC = r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+"
ADDRESS = re.compile("^" + ADDR_SPEC + "$")
# One mailbox: a bare address, or an optional name (quoted, or atoms with no "@") and <address>.
MAILBOX = re.compile(
    r"""^(?:(%s)|(?:"[^"\\]*"|[A-Za-z0-9!#$%%&'*+/=?^_`{|}~ .\t-]*)\s*<(%s)>)$""" % (ADDR_SPEC, ADDR_SPEC)
)
MAX_ID = 512  # bytes; keeps table keys and header lines within their limits
# Untrusted header text is bounded before anything reads it. A header block over the first
# limit is refused with a notice. Only the first occurrence of the fields below is read, as
# plain text; one over the second limit still passes through on the inbound leg, but for
# routing and threading it counts as absent.
MAX_HEADER_BLOCK = 262144
MAX_FIELD = 8192
MAX_REPLY_HEAD = 16384
FIELDS = (
    "from", "reply-to", "sender", "to", "cc", "subject", "references", "in-reply-to",
    "message-id", "auto-submitted", "precedence", "list-id", "content-type",
)
# A bare CR or a control character in the header block: mail software disagrees on where such
# a header ends, so the message is refused with a notice rather than interpreted.
MALFORMED = re.compile(rb"\r(?!\n)|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# The private address as a whole address, not as part of a longer local part or domain.
PRIVATE_NAMED = re.compile(r"(?<![a-z0-9._+-])%s(?![a-z0-9-]|\.[a-z0-9])" % re.escape(PRIVATE.lower()))
SINGLE_SENDER = ("from", "reply-to", "sender")  # a second occurrence makes the field unusable
SEGMENT = re.compile(r"""([A-Za-z0-9._-]+)\*(\d{1,4})\*?\s*=\s*("(?:[^"\\]|\\.)*"|[^;\s]*)""")
TOKEN = re.compile(r"^[a-z2-7]{26}$")
AR_TOKEN = re.compile(r"^[A-Za-z0-9.-]+=[A-Za-z0-9@._+=:/-]+$")

INBOUND_DROP = {
    "from", "to", "reply-to", "cc", "bcc", "sender", "return-path", "delivered-to",
    "dkim-signature", "domainkey-signature", "authentication-results", "received-spf",
    "content-length", "auto-submitted", "message-id", "in-reply-to", "references",
    "list-unsubscribe", "list-unsubscribe-post", "disposition-notification-to",
    "return-receipt-to",
}
INBOUND_DROP_PREFIXES = ("arc-", "x-ses-", "resent-", "x-relay-")
# SES rejects a second occurrence of these fields.
SINGLE = {"subject", "date", "mime-version", "list-id", "content-type", "content-transfer-encoding"}


def error_code(error):
    return (getattr(error, "response", None) or {}).get("Error", {}).get("Code", "")


def permanent(error):
    status = (getattr(error, "response", None) or {}).get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    code = error_code(error)
    # Retried, not consumed: a missing IAM permission (403) or a paused or suspended account
    # is fixed outside the function, and the message should still go once it is.
    retryable = ("Throttl", "Limit", "Suspended", "Paused", "Expired", "Timeout", "Signature")
    return 400 <= status < 500 and status not in (403, 408, 429) and not any(word in code for word in retryable)


def decode_text(value):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("ascii", "replace")


def fields(groups):
    """The first occurrence of each field the relay reads, unfolded, when within MAX_FIELD."""
    found = {}
    for name, lines in groups:
        if name in FIELDS and name not in found:
            fits = sum(len(line) + 2 for line in lines) <= MAX_FIELD
            value = b" ".join(line.strip() for line in lines).split(b":", 1)[1].strip()
            found[name] = decode_text(value) if fits else None
    for name in SINGLE_SENDER:
        if count(groups, name) > 1:
            found[name] = None
    return {name: value for name, value in found.items() if value is not None}


def values(parsed, name):
    value = parsed.get(name.lower())
    return [] if value is None else [value]


def text(parsed, name, default=""):
    return parsed.get(name.lower(), default)


def decode_name(name):
    try:
        name = str(make_header(decode_header(name)))
    except Exception:
        pass
    return name.encode("utf-8", "replace").decode("utf-8")  # a lone surrogate cannot be sent


@lru_cache(maxsize=32)
def address_pairs(value):
    """(display name, address) pairs of one header value, with the names decoded."""
    try:
        found = getaddresses([value])
    except Exception:
        return ()
    return tuple((decode_name(name), address) for name, address in found)


def valid_address(texts):
    """The single address in the given header values, or None when there is not exactly one."""
    found = [pair for value in texts for pair in address_pairs(str(value))]
    if len(found) != 1:
        return None
    address = found[0][1]
    if "\r" in address or "\n" in address or "@" not in address:
        return None
    local, domain = address.rsplit("@", 1)
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    address = f"{local}@{domain}"
    if (
        ADDRESS.fullmatch(address)
        and len(address) <= 254
        and ".." not in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    ):
        return address
    return None


def single_mailbox(raw):
    """The address of a header value that is exactly one mailbox, else None."""
    match = MAILBOX.match((raw or "").strip()) if len(raw or "") <= 1000 else None
    return valid_address([match.group(1) or match.group(2)]) if match else None


def split_message(raw):
    """Splits at the first blank line, with LF or CRLF endings; no blank line means no body."""
    match = re.search(rb"\r?\n\r?\n", raw)
    return (raw[:match.start()], raw[match.end():]) if match else (raw, b"")


def header_groups(blob):
    groups = []
    for line in blob.split(b"\n"):  # only LF ends a line; a bare CR stays inside its header
        line = line.rstrip(b"\r")
        if line[:1] in (b" ", b"\t") and groups:
            groups[-1][1].append(line)
        elif b":" in line:
            try:
                name = line.split(b":", 1)[0].decode("ascii").strip().lower()
            except UnicodeDecodeError:
                name = ""  # not a field the relay reads; it passes through on the inbound leg
            groups.append((name, [line]))
    return groups


def count(groups, name):
    return sum(1 for header, _ in groups if header == name)


def raw_values(groups, name):
    return [
        b" ".join(line.strip() for line in lines).split(b":", 1)[1].strip().decode("ascii", "replace")
        for header, lines in groups if header == name
    ]


def top_value(groups, name):
    found = raw_values(groups, name)
    return found[0] if found else None


def ids(value):
    return re.findall(r"<([^<>\s]+)>", value or "")


def addresses(parsed, name):
    return [address.lower() for value in values(parsed, name) for _, address in address_pairs(value) if address]


def is_own(address):
    address = (address or "").lower().rstrip(".")
    if address == PRIVATE.lower():
        return True
    local, _, domain = address.rpartition("@")
    base = local.split("+", 1)[0]
    return domain == DOMAIN and (base in ("reply", "relay") or f"{base}@{DOMAIN}" in ALIASES)


def is_alias(address):
    local, _, domain = (address or "").lower().rstrip(".").rpartition("@")
    return domain == DOMAIN and local.split("+", 1)[0] + "@" + DOMAIN in ALIASES


def aligned_dkim(value):
    """True when SES's own Authentication-Results proves DKIM aligned with the private domain.

    Sender-chosen values (envelope-from, helo, the SPF comment) sit before SES's dkim and
    dmarc results, so the header is held to a strict grammar, the final entry must be SES's
    dmarc=pass for the private domain, and every dkim entry must be an aligned pass: a forged
    entry cannot hide beside a real one for another domain. Anything else fails closed.
    """
    if value is None or any(c in '"\\' or not 32 <= ord(c) <= 126 for c in value):
        return False
    # SES writes one comment, inside its spf entry. Any other parenthesis is not SES's.
    if value.count("(") > 1 or ("(" in value and value[:value.index("(")].count(";") != 1):
        return False
    depth, plain = 0, []
    for char in value:
        if char == "(":
            if depth:
                return False
            depth = 1
        elif char == ")":
            if not depth:
                return False
            depth = 0
        elif not depth:
            plain.append(char)
    if depth:
        return False
    entries = [entry.split() for entry in "".join(plain).split(";")]
    if entries[0] != ["amazonses.com"]:
        return False
    entries = [entry for entry in entries[1:] if entry]
    if not entries or any(not AR_TOKEN.match(token) for entry in entries for token in entry):
        return False
    if [token.lower() for token in entries[-1]] != ["dmarc=pass", "header.from=" + PRIVATE_DOMAIN]:
        return False
    methods = [entry[0].partition("=")[0].lower() for entry in entries]
    properties = [token.partition("=")[0].lower() for entry in entries for token in entry[1:]]
    if methods.count("dmarc") != 1 or any(name in ("spf", "dkim", "dmarc") for name in properties):
        return False  # a result may only open an entry, and SES reports DMARC once

    def aligned(entry):
        domains = [
            token.partition("=")[2].rsplit("@", 1)[-1].lower()
            for token in entry[1:] if token.partition("=")[0].lower() in ("header.i", "header.d")
        ]
        return bool(domains) and all(
            domain == PRIVATE_DOMAIN or domain.endswith("." + PRIVATE_DOMAIN) for domain in domains
        )

    signatures = [entry for entry in entries if entry[0].lower().startswith("dkim=")]
    return bool(signatures) and all(entry[0] == "dkim=pass" and aligned(entry) for entry in signatures)


def operator_auth(recipient, mail, receipt, groups, parsed):
    """Returns None when the message is proven to come from the private inbox, else a reason."""
    def status(name):
        return receipt.get(name, {}).get("status")

    if status("virusVerdict") != "PASS" or status("spamVerdict") == "FAIL":
        return "scan"
    if status("dkimVerdict") != "PASS" or status("dmarcVerdict") == "FAIL":
        return "verdict"
    if not aligned_dkim(top_value(groups, "authentication-results")):
        return "dkim-alignment"
    if count(groups, "from") != 1 or max(count(groups, n) for n in ("sender", "to", "cc")) > 1:
        return "duplicate-header"
    # Read from the raw value under a strict grammar: address parsers differ between Python
    # releases on forms such as "a@x <b@y>".
    if single_mailbox(top_value(groups, "from")) != PRIVATE:
        return "from"
    if count(groups, "sender") and single_mailbox(top_value(groups, "sender")) != PRIVATE:
        return "sender"
    if not ADDRESS.fullmatch(mail.get("source") or ""):
        return "envelope-sender"
    if recipient not in addresses(parsed, "To") + addresses(parsed, "Cc"):
        return "recipient-not-in-header"
    return None


def outbound_refusal(parsed):
    auto = text(parsed, "Auto-Submitted", "no").split(";")[0].strip().lower()
    if auto != "no":
        return "auto-submitted"
    if text(parsed, "Precedence").strip().lower() in ("bulk", "junk", "list", "auto_reply"):
        return "precedence"
    if text(parsed, "List-Id"):
        return "list"
    if text(parsed, "Content-Type").strip().lower().startswith("multipart/report"):
        return "report"
    return None


def inbound_quarantine(receipt):
    def status(name):
        return receipt.get(name, {}).get("status")

    return (
        status("virusVerdict") != "PASS"
        or status("spamVerdict") == "FAIL"
        or (status("dmarcVerdict") == "FAIL" and receipt.get("dmarcPolicy") in ("reject", "quarantine"))
    )


def get_or_mint_token(alias, peer):
    pair = f"p#{alias}#{peer.lower()}"
    item = table.get_item(Key={"pk": pair}).get("Item")
    if item:
        return item["token"]
    token = base64.b32encode(secrets.token_bytes(16)).decode().rstrip("=").lower()
    table.put_item(Item={"pk": f"t#{token}", "alias": alias, "peer": peer})
    try:
        table.put_item(Item={"pk": pair, "token": token}, ConditionExpression="attribute_not_exists(pk)")
        return token
    except Exception as error:
        if error_code(error) != "ConditionalCheckFailedException":
            raise
        # A concurrent first contact won; reuse its token. The orphan t# item is harmless.
        return table.get_item(Key={"pk": pair}, ConsistentRead=True)["Item"]["token"]


def claim(key):
    now = int(time.time())
    try:
        table.put_item(
            Item={"pk": key, "created": now, "expires": now + 30 * DAY},
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except Exception as error:
        if error_code(error) != "ConditionalCheckFailedException":
            raise
        return False


def wrap(message_id):
    encoded = base64.b32encode(message_id.encode()).decode().rstrip("=").lower()
    return f"<x.{encoded}@{REF_DOMAIN}>"


def unwrap(message_id):
    local, _, domain = message_id.rpartition("@")
    if domain != REF_DOMAIN or not local.startswith("x."):
        return None
    encoded = local[2:].upper()
    try:
        value = base64.b32decode(encoded + "=" * (-len(encoded) % 8)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not value or any(not 32 < ord(c) < 127 or c in "<>" for c in value):
        return None
    return f"<{value}>"


def translate_in(parsed):
    def translate(message_id):
        item = table.get_item(Key={"pk": "o#" + message_id.split("@")[0]}).get("Item")
        return item["mid"] if item else wrap(message_id)

    def short(found):  # an over-long id is not threaded: it would not fit a table key or a header line
        return [message_id for message_id in found if len(message_id.encode("utf-8", "replace")) <= MAX_ID]

    references = short(ids(text(parsed, "References")))
    parents = short(ids(text(parsed, "In-Reply-To")))
    own = short(ids(text(parsed, "Message-ID")))[:1]
    chain = []
    for message_id in (references + [p for p in parents if p not in references])[-20:] + own:
        translated = translate(message_id)
        if translated not in chain and len(translated) < 900:
            chain.append(translated)
    parent = translate(parents[-1]) if parents else None
    return chain, parent if parent and len(parent) < 900 else None


def translate_out(parsed):
    chain = []
    for message_id in ids(text(parsed, "References")) + ids(text(parsed, "In-Reply-To")):
        original = unwrap(message_id)
        if original and original not in chain:
            chain.append(original)
    return chain


def display_text(text):
    """Text for a display name that no mail client can read as, or decode into, another address.

    A display name holding an address other than the header's real one is hidden by some
    providers and counts as a spoofing sign, so "@" and its look-alikes become " at ", and an
    encoded word is broken up so a client cannot decode one inside the name.
    """
    # Nothing a lenient reader could drop to rejoin "=?": control characters, backslashes, and
    # the double quote, which would otherwise be written as a backslash escape.
    text = re.sub(r'[\x00-\x1f\x7f-\x9f\\"]', " ", text)
    return re.sub("[@\uff20\ufe6b]", " at ", text).replace("=?", "= ?")


def address_header(name, address):
    name = re.sub(r"[\r\n\t]+", " ", name or "").strip()
    if not name:
        return address
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        # Folded into encoded words of at most 75 characters, as RFC 2047 requires.
        words = Header(name, "utf-8", maxlinelen=66, header_name="From").encode()
        return words.replace("\n", "\r\n") + f"\r\n <{address}>"
    return formataddr((name, address))


def thread_headers(chain, parent):
    headers = []
    if chain:
        headers.append("References: " + "\r\n ".join(chain))
    if parent:
        headers.append("In-Reply-To: " + parent)
    return headers


def assemble(headers, kept, body):
    lines = [header.encode("ascii") for header in headers] + kept
    return b"\r\n".join(lines), b"\r\n\r\n" + body


def rewrite_inbound(groups, parsed, body, token, peer, gray):
    reply_address = f"reply+{token}@{DOMAIN}"
    found = [pair for value in values(parsed, "From") for pair in address_pairs(value)]
    name = found[0][0].strip() if found else ""
    if name.lower() == peer.lower():
        name = ""  # a name that is only the address is shown once
    name = display_text(name)[:70].strip()  # cut the name, never the correspondent after it
    shown = display_text(" at ".join(peer.rsplit("@", 1)))
    kept, seen = [], set()
    for header, lines in groups:
        if header in INBOUND_DROP or header.startswith(INBOUND_DROP_PREFIXES) or header in seen:
            continue
        if header in SINGLE:
            seen.add(header)
        kept.extend(lines)
    headers = [
        "From: " + address_header(f"{name} ({shown})" if name else shown, reply_address),
        "To: " + PRIVATE,
        "Reply-To: " + reply_address,
    ]
    for name_, source in (("X-Relay-Original-To", "To"), ("X-Relay-Original-Cc", "Cc")):
        original = ", ".join(addresses(parsed, source)).encode("ascii", "ignore").decode()[:800]
        if original:
            headers.append(f"{name_}: {original}")
    headers += thread_headers(*translate_in(parsed))
    headers += ["Auto-Submitted: auto-forwarded", "X-Relay-Hop: v1"]
    if gray:
        headers.append("X-Relay-Spam: gray")
    return assemble(headers, kept, body)


def rewrite_outbound(groups, parsed, body, alias, peer):
    kept, seen = [], set()
    for header, lines in groups:
        allowed = header in ("subject", "mime-version") or (
            header.startswith("content-") and header != "content-length"
        )
        if allowed and header not in seen:
            seen.add(header)
            kept.extend(lines)
    chain = translate_out(parsed)
    headers = ["From: " + address_header(ALIAS_NAME, alias), "To: " + peer]
    headers += thread_headers(chain, chain[-1] if chain else None)
    headers.append("X-Relay-Hop: v1")
    return assemble(headers, kept, body) + (b"\r\n".join(kept),)


def parse_compose(label):
    local, _, domain = label.rpartition("=")
    return valid_address([f"{local}@{domain}"]) if local and domain else None


def send(recipient, data):
    # SES writes FromEmailAddress over the message's own From header, so it is given that
    # header's whole value, display name included: a bare address here would strip the name.
    # Every message the relay builds starts with its From header.
    lines = data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    if not lines[0].lower().startswith(b"from:"):
        raise ValueError("generated message does not start with From")
    parts = [lines[0][5:]]
    for line in lines[1:]:
        if line[:1] not in (b" ", b"\t"):
            break
        parts.append(line)
    response = ses.send_email(
        FromEmailAddress=b" ".join(part.strip() for part in parts).decode("ascii"),
        Destination={"ToAddresses": [recipient]},
        Content={"Raw": {"Data": data}},
    )
    return response["MessageId"]


def deliver(recipient, data, key):
    """Sends once under a claim. Returns the SES id, or None on a permanent reject."""
    try:
        return send(recipient, data)
    except Exception as error:
        if permanent(error):
            logger.warning("send rejected: %s", error_code(error))
            return None
        table.delete_item(Key={"pk": key})
        raise


def encoded_word_leak(block):
    try:
        return PRIVATE.lower() in str(make_header(decode_header(block.decode("ascii", "replace")))).lower()
    except Exception:
        return True


@lru_cache(maxsize=4)
def kept_leak(kept):
    """True when the headers kept from the operator's message name the private address once decoded.

    The parser runs only here, on at most MAX_REPLY_HEAD bytes, once per message; any error it
    raises refuses the reply.
    """
    needle = PRIVATE.lower()
    if encoded_word_leak(kept):
        return True
    try:
        block = BytesHeaderParser(policy=policy.default).parsebytes(kept + b"\r\n\r\n")
        for name, value in block.items():
            params = " ".join(str(param) for param in getattr(value, "params", {}).values())
            if needle in f"{value} {params}".lower():
                return True
    except Exception:
        return True
    # Continued parameters (name*0, name*1), joined by hand: lenient clients reassemble forms the
    # parser does not.
    segments = {}
    for name, index, value in SEGMENT.findall(re.sub(r"\r?\n[ \t]+", " ", kept.decode("ascii", "replace"))):
        segments.setdefault(name.lower(), []).append((int(index), value.strip('"').replace("\\", "")))
    joined = " ".join("".join(value for _, value in sorted(parts)) for parts in segments.values())
    return needle.encode() in unquote_to_bytes(joined).lower()


def leaks_private(head, kept):
    """True when the outgoing header block names the private address, literally or once decoded."""
    needle = PRIVATE.lower().encode()
    plain = head.replace(b"\\", b"")  # a quoted pair hides nothing
    if needle in plain.lower() or needle in unquote_to_bytes(plain).lower():
        return True
    generated = head[:len(head) - len(kept)]  # the kept headers are checked once, in kept_leak
    return encoded_word_leak(generated) or kept_leak(kept)


def notify(reason, mail):
    key = f"d#notice#{mail.get('messageId', '')}#{reason}"
    if not claim(key):
        return
    message = EmailMessage()
    message["From"] = formataddr(("Mail relay", f"relay@{DOMAIN}"))
    message["To"] = PRIVATE
    message["Subject"] = f"Relay notice: {reason}"
    message["Auto-Submitted"] = "auto-generated"
    message["X-Relay-Hop"] = "v1"
    subject = re.sub(r"\s+", " ", str((mail.get("commonHeaders") or {}).get("subject", "")))[:200]
    body = (
        f"The relay did not deliver a message.\n\nReason: {reason}\n"
        f"Sender: {mail.get('source', '')}\nSubject: {subject}\n"
        f"Stored copy: s3://{BUCKET}/{PREFIX}{mail.get('messageId', '')}\n"
    )
    message.set_content(body.encode("utf-8", "replace").decode("utf-8"))
    try:
        send(PRIVATE, message.as_bytes(policy=policy.SMTP))
    except Exception as error:
        logger.warning("notice not sent: %s", error_code(error) or type(error).__name__)
        table.delete_item(Key={"pk": key})
        if permanent(error):  # never record a message as handled when nobody was told
            raise RuntimeError("notice rejected") from None
        raise  # Lambda delivers the event again, and the notice is retried


def notify_rejected(mail, key):
    """Tells the operator about a permanent reject; if the notice cannot be sent, the send is retried."""
    try:
        notify("rejected", mail)
    except Exception:
        table.delete_item(Key={"pk": key})
        raise


def inbound(recipient, alias, mail, receipt, groups, parsed, body, size):
    if inbound_quarantine(receipt):
        return "quarantined", {}
    origin = addresses(parsed, "From") + [mail.get("source") or ""]
    reply_to = valid_address(values(parsed, "Reply-To"))
    # A site form sends From the alias itself with Reply-To the visitor: that is mail, not a loop.
    form = reply_to and not is_own(reply_to) and all(not is_own(a) or is_alias(a) for a in origin)
    replies = addresses(parsed, "Reply-To")
    # The private address is known only to its owner, so a From that mentions it anywhere,
    # however malformed, is the owner writing to the alias or a forgery: dropped either way.
    named = PRIVATE_NAMED.search(text(parsed, "From").lower())
    if named or (not form and any(is_own(address) for address in origin + replies)):
        if named or any(is_own(a) and not is_alias(a) for a in origin) or any(is_own(a) for a in replies):
            return "dropped:own-address", {}
        # From the alias itself with no usable Reply-To: nobody to answer, but not a loop.
        notify("no-reply-to", mail)
        return "notice:no-reply-to", {}
    peer = reply_to or valid_address(values(parsed, "From")) or valid_address([mail.get("source") or ""])
    if not peer:
        notify("no-sender", mail)
        return "notice:no-sender", {}
    if is_own(peer):
        return "dropped:own-address", {}
    if size > MAX_BYTES:
        notify("oversize", mail)
        return "notice:oversize", {}
    token = get_or_mint_token(alias, peer)
    gray = receipt.get("spamVerdict", {}).get("status") == "GRAY"
    head, rest = rewrite_inbound(groups, parsed, body, token, peer, gray)
    key = f"d#{mail['messageId']}#{recipient}"
    if not claim(key):
        return "duplicate", {"tok": token[:6]}
    sent = deliver(PRIVATE, head + rest, key)
    if not sent:
        notify_rejected(mail, key)
        return "notice:rejected", {"tok": token[:6]}
    return "forwarded", {"tok": token[:6], "out": sent}


def outbound(leg, recipient, argument, mail, groups, parsed, body, size):
    def refuse(reason):
        notify(reason, mail)
        return "notice:" + reason, {}

    refusal = outbound_refusal(parsed)
    if refusal:
        return refuse(refusal)
    if size > MAX_BYTES:
        return refuse("oversize")
    own_ids = ids(top_value(groups, "message-id"))
    if count(groups, "message-id") != 1 or len(own_ids) != 1 or not re.fullmatch(r"[\x21-\x7e]{1,%d}" % MAX_ID, own_ids[0]):
        return refuse("no-message-id")
    token = None
    if leg == "reply":
        item = table.get_item(Key={"pk": "t#" + argument}).get("Item") if TOKEN.match(argument) else None
        if not item or item.get("alias") not in ALIASES:
            return refuse("unknown-token")
        alias, peer, token = item["alias"], item["peer"], argument
    else:
        alias = recipient.split("+", 1)[0] + "@" + DOMAIN
        peer = parse_compose(argument)
        if not peer:
            return refuse("bad-compose-target")
    if is_own(peer):
        return refuse("own-address")
    head, rest, kept = rewrite_outbound(groups, parsed, body, alias, peer)
    if len(head) > MAX_REPLY_HEAD:
        return refuse("header-too-large")
    if leaks_private(head, kept):
        return refuse("header-guard")
    if not OUTBOUND:
        return "dry-run:" + leg, {}
    token = token or get_or_mint_token(alias, peer)
    key = f"d#{own_ids[0]}#{recipient}"
    if not claim(key):
        return "duplicate", {"tok": token[:6]}
    sent = deliver(peer, head + rest, key)
    if not sent:
        notify_rejected(mail, key)
        return "notice:rejected", {}
    try:
        table.put_item(Item={
            "pk": "o#" + sent, "mid": f"<{own_ids[0]}>", "expires": int(time.time()) + 400 * DAY,
        })
    except Exception as error:
        logger.warning("anchor not stored: %s", error_code(error) or type(error).__name__)
    return ("relayed" if leg == "reply" else "composed"), {"tok": token[:6], "out": sent}


def route(recipient, mail, receipt, groups, parsed, body, size):
    local = recipient.rpartition("@")[0]
    base, _, label = local.partition("+")
    if count(groups, "x-relay-hop"):
        return "none", "dropped:own-output", {}
    if base == "reply":
        reason = operator_auth(recipient, mail, receipt, groups, parsed)
        if reason:
            return "reply", "dropped:auth:" + reason, {}
        return ("reply",) + outbound("reply", recipient, label, mail, groups, parsed, body, size)
    alias = f"{base}@{DOMAIN}"
    if alias not in ALIASES:
        return "none", "dropped:unknown-recipient", {}
    if "=" in label and not operator_auth(recipient, mail, receipt, groups, parsed):
        return ("compose",) + outbound("compose", recipient, label, mail, groups, parsed, body, size)
    return ("inbound",) + inbound(recipient, alias, mail, receipt, groups, parsed, body, size)


def process(record):
    mail = record["ses"]["mail"]
    receipt = record["ses"]["receipt"]
    recipients = [r.lower() for r in receipt.get("recipients", []) if r.lower().endswith("@" + DOMAIN)]
    if not recipients:
        logger.info(json.dumps({"leg": "none", "outcome": "dropped:no-relay-recipient", "in": mail["messageId"]}))
        return ["dropped:no-relay-recipient"]
    stored = s3.get_object(Bucket=BUCKET, Key=PREFIX + mail["messageId"])
    size = stored["ContentLength"]
    raw = stored["Body"].read(65536) if size > MAX_BYTES else stored["Body"].read()
    header_blob, body = split_message(raw)
    refusal = (
        "oversize-headers" if len(header_blob) > MAX_HEADER_BLOCK
        else "malformed-headers" if MALFORMED.search(header_blob) else None
    )
    if refusal:
        notify(refusal, mail)
        logger.info(json.dumps({"leg": "none", "outcome": "notice:" + refusal, "in": mail["messageId"]}))
        return ["notice:" + refusal]
    groups = header_groups(header_blob)
    parsed = fields(groups)
    outcomes = []
    for recipient in recipients:
        leg, outcome, extra = route(recipient, mail, receipt, groups, parsed, body, size)
        verdicts = {
            name[:-7]: receipt.get(name, {}).get("status")
            for name in ("spamVerdict", "virusVerdict", "spfVerdict", "dkimVerdict", "dmarcVerdict")
        }
        logger.info(json.dumps(dict(extra, leg=leg, outcome=outcome, verdicts=verdicts, **{"in": mail["messageId"]})))
        outcomes.append(outcome)
    return outcomes


def handler(event, context):
    results = []
    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:ses":
            raise ValueError("unexpected event source")
        results.extend(process(record))
    return {"results": results}
