"""Unit tests for src/relay.py. Standard library only: AWS clients are replaced by fakes."""
import ast
import email
import email.header
import email.utils
import hashlib
import importlib.util
import io
import os
import pathlib
import re
import sys
import time
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class FakeError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeS3:
    def __init__(self):
        self.objects, self.lengths = {}, {}

    def get_object(self, Bucket, Key):
        data = self.objects[Key]
        return {"ContentLength": self.lengths.get(Key, len(data)), "Body": io.BytesIO(data)}


class FakeSes:
    def __init__(self):
        self.sent, self.errors, self.params = [], [], []

    def send_email(self, FromEmailAddress, Destination, Content):
        if self.errors:
            raise self.errors.pop(0)
        self.params.append(FromEmailAddress)  # as passed; SES uses it as the message's From
        address = email.utils.parseaddr(FromEmailAddress)[1]
        self.sent.append((address, Destination["ToAddresses"], Content["Raw"]["Data"]))
        return {"MessageId": f"ses{len(self.sent)}"}


class FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get(Key["pk"])
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None):
        if ConditionExpression and Item["pk"] in self.items:
            raise FakeError("ConditionalCheckFailedException", 400)
        self.items[Item["pk"]] = dict(Item)

    def delete_item(self, Key):
        self.items.pop(Key["pk"], None)


S3, SES, TABLE = FakeS3(), FakeSes(), FakeTable()
boto3 = types.ModuleType("boto3")
boto3.client = lambda name, **kwargs: {"s3": S3, "sesv2": SES}[name]
boto3.resource = lambda name: types.SimpleNamespace(Table=lambda table_name: TABLE)
botocore = types.ModuleType("botocore")
botocore_config = types.ModuleType("botocore.config")
botocore_config.Config = lambda **kwargs: None
sys.modules.update({"boto3": boto3, "botocore": botocore, "botocore.config": botocore_config})
os.environ.update({
    "BUCKET": "bucket", "TABLE": "table", "DOMAIN": "example.com", "ALIASES": "you@example.com",
    "ALIAS_NAME": "You", "PRIVATE": "private@example.net", "OUTBOUND": "true",
})


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


relay = load("relay", "src/relay.py")
render = load("render", "scripts/render.py")

AUTH = (
    "amazonses.com; spf=none (spfCheck: 209.85.217.47 is neither permitted nor denied by domain of "
    "example.net) client-ip=209.85.217.47; envelope-from=private@example.net; "
    "helo=mail-vs1-f47.google.com; dkim=pass header.i=@example.net; dmarc=pass header.from=example.net;"
)
PASS = {"spam": "PASS", "virus": "PASS", "spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
BODY = b"Hello\r\n\r\nSecond paragraph.\r\n"


def message(headers, body=BODY):
    return "\r\n".join(f"{name}: {value}" for name, value in headers).encode() + b"\r\n\r\n" + body


def inbound_message(extra=(), sender="Bob <bob@example.org>", message_id="<c1@bob.example>", body=BODY):
    return message([
        ("Received", "from mx.example.org by inbound-smtp.us-east-1.amazonaws.com"),
        ("From", sender), ("To", "you@example.com"), ("Subject", "Hi"),
        ("Message-ID", message_id), ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ] + list(extra), body)


def reply_message(to, extra=(), auth=AUTH, sender="Me <private@example.net>", message_id="<p1@mail.gmail.com>"):
    headers = [("Authentication-Results", auth)] if auth else []
    headers += [
        ("Received", "from mail-vs1-f47.google.com by inbound-smtp.us-east-1.amazonaws.com"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; d=example.net; s=google; h=to:from:to:cc; b=abc"),
        ("X-Google-DKIM-Signature", "v=1; d=1e100.net; b=def"), ("X-Gm-Message-State", "state"),
        ("MIME-Version", "1.0"), ("From", sender), ("Date", "Sun, 15 Nov 2026 10:00:00 -0500"),
        ("Subject", "Re: Hi"), ("To", to), ("Content-Type", "text/plain; charset=utf-8"),
    ]
    if message_id:
        headers.append(("Message-ID", message_id))
    return message(headers + list(extra))


class RelayTest(unittest.TestCase):
    def setUp(self):
        S3.objects.clear()
        S3.lengths.clear()
        SES.sent.clear()
        SES.params.clear()
        SES.errors.clear()
        TABLE.items.clear()
        relay.OUTBOUND = True
        self.counter = 0

    def event(self, raw, recipients, source="bob@example.org", length=None, **verdicts):
        self.counter += 1
        key = f"in{self.counter}"
        S3.objects["raw/" + key] = raw
        if length:
            S3.lengths["raw/" + key] = length
        receipt = {"recipients": recipients}
        for name, status in dict(PASS, **verdicts).items():
            if name == "policy":
                receipt["dmarcPolicy"] = status
            else:
                receipt[name + "Verdict"] = {"status": status}
        mail = {"messageId": key, "source": source, "commonHeaders": {"subject": "Hi"}}
        return {"Records": [{"eventSource": "aws:ses", "ses": {"mail": mail, "receipt": receipt}}]}

    def run_message(self, raw, recipients=("you@example.com",), **kwargs):
        return relay.handler(self.event(raw, list(recipients), **kwargs), None)["results"]

    def token(self, alias="you@example.com", peer="bob@example.org"):
        return TABLE.items[f"p#{alias}#{peer}"]["token"]

    def first_contact(self):
        self.assertEqual(self.run_message(inbound_message()), ["forwarded"])
        return f"reply+{self.token()}@example.com"

    def reply(self, to=None, **kwargs):
        to = to or self.first_contact()
        source = kwargs.pop("source", "private@example.net")
        verdicts = kwargs.pop("verdicts", {})
        return self.run_message(reply_message(to, **kwargs), [to], source=source, **verdicts)

    @staticmethod
    def parsed(index=-1):
        return email.message_from_bytes(SES.sent[index][2])

    @staticmethod
    def header(name, index=-1):
        return " ".join((RelayTest.parsed(index)[name] or "").split())

    def notices(self):
        return [RelayTest.parsed(i)["Subject"] for i, sent in enumerate(SES.sent) if sent[0] == "relay@example.com"]

    def test_u1_inbound_plain_text(self):
        self.first_contact()
        sender, recipients, data = SES.sent[0]
        self.assertRegex(self.header("From"), r'^"Bob \(bob at example\.org\)" <reply\+[a-z2-7]{26}@example\.com>$')
        self.assertEqual(sender, f"reply+{self.token()}@example.com")
        self.assertEqual((recipients, self.header("To")), (["private@example.net"], "private@example.net"))
        self.assertEqual(self.header("Reply-To"), sender)
        self.assertEqual(hashlib.sha256(data.split(b"\r\n\r\n", 1)[1]).digest(), hashlib.sha256(BODY).digest())
        item = TABLE.items["t#" + self.token()]
        self.assertEqual((item["alias"], item["peer"]), ("you@example.com", "bob@example.org"))
        self.assertEqual(self.header("X-Relay-Hop"), "v1")

    def test_u2_multipart_bodies_pass_through(self):
        body = (b"--b1\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:i1\">\r\n--b1\r\n"
                b"Content-Type: image/png\r\nContent-ID: <i1>\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                b"iVBORw0KGgo=\r\n--b1\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.7\r\n--b1--\r\n")
        raw = inbound_message(body=body).replace(b"text/plain; charset=utf-8", b"multipart/mixed; boundary=b1")
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertEqual(SES.sent[0][2].split(b"\r\n\r\n", 1)[1], body)
        self.assertEqual(self.header("Content-Type"), "multipart/mixed; boundary=b1")

    def test_u3_reply_to_is_the_peer(self):
        raw = inbound_message([("Reply-To", "alice@example.org")], sender="Forms <no-reply@forms.example>")
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertEqual(TABLE.items["t#" + self.token(peer="alice@example.org")]["peer"], "alice@example.org")
        self.assertIn("(alice at example.org)", self.header("From"))

    def test_u4_inbound_strips_headers(self):
        raw = inbound_message([
            ("Cc", "carol@example.org"), ("Bcc", "dave@example.org"),
            ("List-Unsubscribe", "<mailto:leave@list.example>"),
            ("Disposition-Notification-To", "bob@example.org"), ("Return-Path", "<bob@example.org>"),
            ("DKIM-Signature", "v=1; d=example.org; b=x"), ("X-SES-Spam-Verdict", "PASS"),
            ("X-Relay-Spam", "gray"),
        ])
        self.assertEqual(self.run_message(raw), ["forwarded"])
        sent = self.parsed()
        for name in ("Cc", "Bcc", "List-Unsubscribe", "Disposition-Notification-To", "Return-Path",
                     "DKIM-Signature", "X-SES-Spam-Verdict", "Message-ID", "X-Relay-Spam"):
            self.assertIsNone(sent[name], name)
        self.assertEqual(sent["X-Relay-Original-Cc"], "carol@example.org")
        self.assertEqual(sent["X-Relay-Original-To"], "you@example.com")
        self.assertIsNotNone(sent["Received"])

    def test_u5_auto_reply_and_duplicate_subject(self):
        raw = inbound_message([("Auto-Submitted", "auto-replied"), ("Subject", "Second")])
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertEqual(self.parsed().get_all("Auto-Submitted"), ["auto-forwarded"])
        self.assertEqual(self.parsed().get_all("Subject"), ["Hi"])

    def test_u5_spam_gray_is_marked_and_fail_is_quarantined(self):
        self.assertEqual(self.run_message(inbound_message(), spam="GRAY"), ["forwarded"])
        self.assertEqual(self.header("X-Relay-Spam"), "gray")
        for verdicts in ({"spam": "FAIL"}, {"virus": "FAIL"}, {"dmarc": "FAIL", "policy": "reject"}):
            self.assertEqual(self.run_message(inbound_message(), **verdicts), ["quarantined"])
        self.assertEqual(self.run_message(inbound_message(), dmarc="FAIL", policy="none"), ["forwarded"])
        self.assertEqual(len(SES.sent), 2)

    def test_u6_token_is_stable_per_pair(self):
        relay.ALIASES.append("info@example.com")
        self.addCleanup(relay.ALIASES.remove, "info@example.com")
        self.run_message(inbound_message())
        first = self.token()
        self.run_message(inbound_message(message_id="<c2@bob.example>"))
        self.assertEqual(self.token(), first)
        self.run_message(inbound_message(), ["info@example.com"])
        self.assertNotEqual(self.token("info@example.com"), first)
        self.assertEqual(len([key for key in TABLE.items if key.startswith("t#")]), 2)

    def test_u7_outbound_keeps_only_the_allowlist(self):
        self.assertEqual(self.reply(extra=[("Reply-To", "private@example.net"), ("User-Agent", "Gmail")]), ["relayed"])
        sender, recipients, data = SES.sent[-1]
        self.assertEqual((sender, recipients), ("you@example.com", ["bob@example.org"]))
        head = data.split(b"\r\n\r\n", 1)[0].lower()
        for leak in (b"private@example.net", b"example.net", b"gmail", b"google", b"x-gm", b"received", b"dkim"):
            self.assertNotIn(leak, head)
        self.assertEqual(sorted(name.lower() for name in self.parsed().keys()),
                         ["content-type", "from", "mime-version", "subject", "to", "x-relay-hop"])
        self.assertEqual(self.header("From"), "You <you@example.com>")
        self.assertEqual(data.split(b"\r\n\r\n", 1)[1], BODY)

    def test_u8_threading_trace(self):
        w1, w2 = relay.wrap("c1@bob.example"), relay.wrap("c2@bob.example")
        to = self.first_contact()
        self.assertEqual((self.header("References"), self.header("In-Reply-To")), (w1, ""))
        ses1 = "<ses1@email.amazonses.com>"
        self.reply(to, extra=[("References", f"{w1} {ses1}"), ("In-Reply-To", ses1)])
        self.assertEqual((self.header("References"), self.header("In-Reply-To")),
                         ("<c1@bob.example>", "<c1@bob.example>"))
        self.assertEqual(TABLE.items["o#ses2"]["mid"], "<p1@mail.gmail.com>")
        ses2 = "<ses2@email.amazonses.com>"
        self.run_message(inbound_message([("References", f"<c1@bob.example> {ses2}"), ("In-Reply-To", ses2)],
                                         message_id="<c2@bob.example>"))
        self.assertEqual(self.header("References"), f"{w1} <p1@mail.gmail.com> {w2}")
        self.assertEqual(self.header("In-Reply-To"), "<p1@mail.gmail.com>")
        refs = f"{w1} <p1@mail.gmail.com> {w2} <ses3@email.amazonses.com>"
        self.reply(to, message_id="<p2@mail.gmail.com>",
                   extra=[("References", refs), ("In-Reply-To", "<ses3@email.amazonses.com>")])
        self.assertEqual(self.header("References"), "<c1@bob.example> <c2@bob.example>")
        self.assertEqual(self.header("In-Reply-To"), "<c2@bob.example>")

    def test_unwrap_rejects_foreign_and_malformed_ids(self):
        self.assertEqual(relay.unwrap(relay.wrap("a@b")[1:-1]), "<a@b>")
        for bad in ("a@b", "x.!!!@ref.example.com", "x.@ref.example.com", "y.mfra@ref.example.com",
                    relay.wrap("a<b@c")[1:-1], relay.wrap("a b@c")[1:-1], "x.77777777@ref.example.com"):
            self.assertIsNone(relay.unwrap(bad), bad)

    def test_u9_authentication_failures_are_dropped_silently(self):
        to = self.first_contact()
        forged = "dkim=pass header.i=@example.net"
        cases = {
            "scan": {"verdicts": {"virus": "FAIL"}},
            "verdict": {"verdicts": {"dkim": "FAIL"}},
            "verdict-gray": {"verdicts": {"dkim": "GRAY"}},
            "verdict-dmarc": {"verdicts": {"dmarc": "FAIL"}},
            "missing header": {"auth": None},
            "other domain": {"auth": AUTH.replace("header.i=@example.net", "header.i=@example.org")},
            "suffix domain": {"auth": AUTH.replace("header.i=@example.net", "header.i=@example.net.evil")},
            "prefix domain": {"auth": AUTH.replace("header.i=@example.net", "header.i=@notexample.net")},
            "dkim fail": {"auth": AUTH.replace("dkim=pass", "dkim=fail")},
            "dmarc not pass": {"auth": AUTH.replace("dmarc=pass", "dmarc=none")},
            "dmarc other domain": {"auth": AUTH.replace("header.from=example.net", "header.from=example.org")},
            "authserv suffix": {"auth": AUTH.replace("amazonses.com;", "amazonses.com.evil;", 1)},
            "authserv prefix": {"auth": "x" + AUTH},
            "via envelope-from": {"auth": AUTH.replace("envelope-from=private@example.net",
                                                       f"envelope-from=a; {forged}; b=c@evil.example")
                                          .replace("dkim=pass header.i=@example.net; dmarc=pass",
                                                   "dkim=pass header.i=@evil.example; dmarc=fail")},
            "via helo": {"auth": AUTH.replace("helo=mail-vs1-f47.google.com", f"helo=x; {forged}")
                                     .replace("; dmarc=pass header.from=example.net", "; dmarc=fail header.from=example.net")},
            "in comment": {"auth": AUTH.replace("(spfCheck:", f"(; {forged}; spfCheck:")
                                       .replace("dkim=pass header.i=@example.net; dmarc", "dkim=fail; dmarc")},
            "quoted string": {"auth": AUTH.replace("helo=mail-vs1-f47.google.com", 'helo="x"')},
            "nested comment": {"auth": AUTH.replace("(spfCheck:", "((spfCheck:")},
            "unbalanced comment": {"auth": AUTH + " )"},
            "trailing entry": {"auth": AUTH + " x=y;"},
            "from": {"sender": "Me <other@example.net>"},
            "two addresses": {"sender": "private@example.net, eve@evil.example"},
            "two from headers": {"extra": [("From", "eve@evil.example")]},
            "two to headers": {"extra": [("To", to)]},
            "sender mismatch": {"extra": [("Sender", "eve@evil.example")]},
            "empty envelope": {"source": ""},
            "odd envelope": {"source": "a;b@evil.example"},
        }
        for name, kwargs in cases.items():
            with self.subTest(name):
                outcome = self.reply(to, **kwargs)
                self.assertTrue(outcome[0].startswith("dropped:auth:"), outcome)
        raw = reply_message("someone@else.example")
        outcome = self.run_message(raw, [to], source="private@example.net")
        self.assertEqual(outcome, ["dropped:auth:recipient-not-in-header"])
        self.assertEqual(len(SES.sent), 1)

    def test_u9_forged_lower_header_is_ignored(self):
        to = self.first_contact()
        bad = AUTH.replace("dkim=pass", "dkim=fail").replace("dmarc=pass", "dmarc=fail")
        outcome = self.reply(to, auth=bad, extra=[("Authentication-Results", AUTH)])
        self.assertEqual(outcome, ["dropped:auth:dkim-alignment"])

    def test_u10_aligned_dkim_with_dmarc_gray_and_subdomain(self):
        self.assertEqual(self.reply(verdicts={"dmarc": "GRAY"}), ["relayed"])
        self.assertTrue(relay.aligned_dkim(AUTH.replace("header.i=@example.net", "header.d=mail.example.net")))

    def test_u11_unknown_token(self):
        self.first_contact()
        unknown = "reply+" + "a" * 26 + "@example.com"
        self.assertEqual(self.reply(unknown), ["notice:unknown-token"])
        self.assertEqual(self.notices(), ["Relay notice: unknown-token"])
        self.assertEqual(self.reply("reply+short@example.com"), ["notice:unknown-token"])
        stranger = message([("From", "eve@evil.example"), ("To", unknown), ("Subject", "x"), ("Message-ID", "<e@e>")])
        self.assertEqual(self.run_message(stranger, [unknown]), ["dropped:auth:dkim-alignment"])
        self.assertEqual(len(self.notices()), 2)

    def test_u12_compose(self):
        to = "you+bob=example.org@example.com"
        self.assertEqual(self.reply(to), ["composed"])
        self.assertEqual((SES.sent[-1][0], SES.sent[-1][1]), ("you@example.com", ["bob@example.org"]))
        self.assertEqual(TABLE.items["t#" + self.token()]["peer"], "bob@example.org")
        to = "you+a+b=example.org@example.com"
        self.assertEqual(self.reply(to, message_id="<p2@mail.gmail.com>"), ["composed"])
        self.assertEqual(SES.sent[-1][1], ["a+b@example.org"])
        self.assertEqual(self.reply("you+label@example.com"), ["dropped:own-address"])
        self.assertEqual(self.reply("you+x=example.com@example.com"), ["composed"])
        for target in ("you+you=example.com@example.com", "you+private=example.net@example.com",
                       "you+reply=example.com@example.com"):
            self.assertEqual(self.reply(target), ["notice:own-address"], target)
        self.assertEqual(self.reply("you+=example.org@example.com"), ["notice:bad-compose-target"])
        stranger = inbound_message().replace(b"To: you@example.com", b"To: you+bob=example.org@example.com")
        self.assertEqual(self.run_message(stranger, ["you+bob=example.org@example.com"], source="eve@evil.example"),
                         ["forwarded"])
        self.assertEqual(SES.sent[-1][1], ["private@example.net"])

    def test_u13_loops(self):
        to = self.first_contact()
        self.assertEqual(self.run_message(inbound_message([("X-Relay-Hop", "v1")])), ["dropped:own-output"])
        self.assertEqual(self.reply(to, extra=[("X-Relay-Hop", "v1")]), ["dropped:own-output"])
        refusals = {
            "auto-submitted": [("Auto-Submitted", "auto-replied")], "precedence": [("Precedence", "bulk")],
            "list": [("List-Id", "<l.example>")],
        }
        for reason, extra in refusals.items():
            self.assertEqual(self.reply(to, extra=extra), ["notice:" + reason])
        report = reply_message(to).replace(b"text/plain; charset=utf-8", b"multipart/report; boundary=x")
        self.assertEqual(self.run_message(report, [to], source="private@example.net"), ["notice:report"])
        self.assertEqual(self.reply(to, extra=[("Auto-Submitted", "no")]), ["relayed"])
        for extra in refusals.values():
            self.assertEqual(self.run_message(inbound_message(extra, message_id="<c9@bob.example>")), ["forwarded"])
            TABLE.items = {k: v for k, v in TABLE.items.items() if not k.startswith("d#")}

    def test_a4_only_the_relays_own_addresses_are_dropped(self):
        other = inbound_message(sender="Support <support@example.com>")
        self.assertEqual(self.run_message(other, source="support@example.com"), ["forwarded"])
        aliases = ["you@example.com", "You <you+tag@example.com>"]
        others = ["reply+abc@example.com", "relay@example.com", "private@example.net", "PRIVATE@Example.NET"]
        for address in aliases + others:
            with self.subTest(address):
                # From the alias with nobody to answer is reported; every other own address is dropped.
                expected = ["notice:no-reply-to"] if address in aliases else ["dropped:own-address"]
                self.assertEqual(self.run_message(inbound_message(sender=address)), expected)
                self.assertEqual(self.run_message(inbound_message([("Reply-To", address)])), ["dropped:own-address"])
                bare = address.split("<")[-1].rstrip(">")
                self.assertEqual(self.run_message(inbound_message(), source=bare), expected)
        self.assertEqual(len([sent for sent in SES.sent if sent[0] != "relay@example.com"]), 1)
        self.assertEqual(len(self.notices()), 4)
        self.assertEqual(len([key for key in TABLE.items if key.startswith("t#")]), 1)

    def test_u14_duplicates_and_retries(self):
        event = self.event(inbound_message(), ["you@example.com"])
        self.assertEqual(relay.handler(event, None)["results"], ["forwarded"])
        self.assertEqual(relay.handler(event, None)["results"], ["duplicate"])
        self.assertEqual(len(SES.sent), 1)
        retry = self.event(inbound_message(message_id="<c2@bob.example>"), ["you@example.com"])
        SES.errors.append(FakeError("ThrottlingException", 400))
        with self.assertRaises(FakeError):
            relay.handler(retry, None)
        self.assertEqual(relay.handler(retry, None)["results"], ["forwarded"])
        SES.errors.append(Exception("connection reset"))
        with self.assertRaises(Exception):
            relay.handler(self.event(inbound_message(message_id="<c3@bob.example>"), ["you@example.com"]), None)
        self.assertEqual(len(SES.sent), 2)

    def test_u14_permanent_reject_keeps_the_claim_and_notifies(self):
        event = self.event(inbound_message(), ["you@example.com"])
        SES.errors.append(FakeError("MessageRejected", 400))
        self.assertEqual(relay.handler(event, None)["results"], ["notice:rejected"])
        self.assertEqual(self.notices(), ["Relay notice: rejected"])
        self.assertEqual(relay.handler(event, None)["results"], ["duplicate"])
        to = f"reply+{self.token()}@example.com"
        SES.errors.append(FakeError("MessageRejected", 400))
        self.assertEqual(self.reply(to), ["notice:rejected"])

    def test_double_rejection_is_raised_not_swallowed(self):
        to = self.first_contact()
        event = self.event(inbound_message(message_id="<c7@bob.example>"), ["you@example.com"])
        reply = self.event(reply_message(to), [to], source="private@example.net")
        claims = {key for key in TABLE.items if key.startswith("d#")}
        for failing in (event, reply):
            for _ in range(3):
                SES.errors.extend([FakeError("MessageRejected", 400), FakeError("MessageRejected", 400)])
                with self.assertRaises(RuntimeError):
                    relay.handler(failing, None)
                self.assertEqual({key for key in TABLE.items if key.startswith("d#")}, claims)
        self.assertEqual(len(SES.sent), 1)
        self.assertEqual(relay.handler(event, None)["results"], ["forwarded"])

    def test_u14_reply_replay_is_blocked_and_each_recipient_is_handled(self):
        to = self.first_contact()
        self.assertEqual(self.reply(to), ["relayed"])
        self.assertEqual(self.reply(to), ["duplicate"])
        results = self.run_message(inbound_message(message_id="<c5@bob.example>"),
                                   ["you@example.com", "you+tag@example.com", "other@elsewhere.example",
                                    "nobody@example.com"])
        self.assertEqual(results, ["forwarded", "forwarded", "dropped:unknown-recipient"])

    def test_u15_oversize(self):
        self.assertEqual(self.run_message(inbound_message(), length=relay.MAX_BYTES + 1), ["notice:oversize"])
        self.assertEqual(self.notices(), ["Relay notice: oversize"])
        notice = SES.sent[-1][2]
        self.assertNotIn(b"Second paragraph", notice)
        self.assertIn(b"in1", notice)
        to = self.first_contact()
        raw = reply_message(to)
        self.assertEqual(self.run_message(raw, [to], source="private@example.net", length=relay.MAX_BYTES + 1),
                         ["notice:oversize"])
        stranger = reply_message(to, auth=None)
        self.assertEqual(self.run_message(stranger, [to], length=relay.MAX_BYTES + 1), ["dropped:auth:dkim-alignment"])

    def test_u16_non_ascii_names(self):
        raw = inbound_message(sender="=?utf-8?b?SsO8cmdlbiBNw7xsbGVy?= <bob@example.org>")
        self.assertEqual(self.run_message(raw), ["forwarded"])
        head = SES.sent[0][2].split(b"\r\n\r\n", 1)[0]
        head.decode("ascii")
        self.assertIn(b"=?utf-8?", head)
        self.assertTrue(all(len(line) < 1000 for line in head.split(b"\r\n")))
        name = str(email.header.make_header(email.header.decode_header(self.parsed()["From"])))
        self.assertIn("Jürgen Müller (bob at example.org)", name)

    def test_u17_dry_run_sends_nothing(self):
        to = self.first_contact()
        relay.OUTBOUND = False
        self.assertEqual(self.reply(to), ["dry-run:reply"])
        self.assertEqual(self.reply("you+bob=example.org@example.com"), ["dry-run:compose"])
        self.assertEqual(len(SES.sent), 1)
        self.assertFalse([key for key in TABLE.items if key.startswith(("d#<", "d#p", "o#"))])
        self.assertEqual(self.reply(to, auth=None), ["dropped:auth:dkim-alignment"])

    def test_u18_header_guard(self):
        to = self.first_contact()
        raw = reply_message(to).replace(b"Subject: Re: Hi", b"Subject: write to Private@Example.net")
        self.assertEqual(self.run_message(raw, [to], source="private@example.net"), ["notice:header-guard"])
        self.assertEqual(len([sent for sent in SES.sent if sent[0] == "you@example.com"]), 0)

    def test_f8_missing_message_id_is_refused(self):
        to = self.first_contact()
        self.assertEqual(self.reply(to, message_id=None), ["notice:no-message-id"])
        self.assertEqual(self.reply(to, message_id="not-an-id"), ["notice:no-message-id"])

    def test_notice_shape(self):
        self.run_message(inbound_message(), length=relay.MAX_BYTES + 1)
        sender, recipients, _ = SES.sent[-1]
        self.assertEqual((sender, recipients), ("relay@example.com", ["private@example.net"]))
        self.assertEqual((self.header("Auto-Submitted"), self.header("X-Relay-Hop")), ("auto-generated", "v1"))

    def test_log_lines_carry_no_addresses(self):
        with self.assertLogs(level="INFO") as logs:
            self.reply()
        text = "\n".join(logs.output)
        self.assertIn('"outcome": "relayed"', text)
        for leak in ("example.org", "example.net", "private@", "Hi"):
            self.assertNotIn(leak, text)

    def test_malformed_headers_never_raise_or_lose_mail(self):
        for index, extra in enumerate(([("Cc", ",():")], [("Cc", '"')], [("Reply-To", "<")], [("Reply-To", "a@b, c")])):
            with self.subTest(extra):
                raw = inbound_message(extra, message_id=f"<m{index}@bob.example>")
                self.assertEqual(self.run_message(raw), ["forwarded"])
        for sender in ("<", '"', "bob@example.org, eve"):
            with self.subTest(sender):
                self.assertEqual(self.run_message(inbound_message(sender=sender, message_id="<n@bob.example>")),
                                 ["forwarded"])
                TABLE.items = {k: v for k, v in TABLE.items.items() if not k.startswith("d#")}
        self.assertEqual(self.run_message(inbound_message(sender="<"), source=""), ["notice:no-sender"])
        self.assertEqual(self.notices(), ["Relay notice: no-sender"])
        two_authors = inbound_message(sender="a@x.example, b@y.example", message_id="<null@bob.example>")
        self.assertEqual(self.run_message(two_authors, source="<>"), ["notice:no-sender"])

    def test_every_dkim_entry_must_be_an_aligned_pass(self):
        to = self.first_contact()
        forged = AUTH.replace("helo=mail-vs1-f47.google.com; dkim=pass header.i=@example.net;",
                              "helo=x; dkim=pass header.i=@example.net; dkim=pass header.i=@evil.example;")
        self.assertNotEqual(forged, AUTH)
        for auth in (forged, AUTH.replace("dkim=pass header.i=@example.net;",
                                          "dkim=pass header.i=@example.net; dkim=fail header.i=@example.net;"),
                     AUTH.replace(" dkim=pass header.i=@example.net;", "")):
            self.assertEqual(self.reply(to, auth=auth), ["dropped:auth:dkim-alignment"])
        two = AUTH.replace("dkim=pass header.i=@example.net;",
                           "dkim=pass header.i=@example.net; dkim=pass header.d=mail.example.net;")
        self.assertEqual(self.reply(to, auth=two), ["relayed"])

    def test_address_lists_and_groups_are_not_the_operator(self):
        to = self.first_contact()
        for sender in ("private@example.net, eve", "private@example.net, <eve>", "eve: private@example.net;",
                       "private@example.net <eve@example.net>", "private@example.net eve@evil.example",
                       "<private@example.net> <eve@evil.example>", "Me (x) <private@example.net>",
                       '"a\\"b" <private@example.net>', "Me <private@example.net> x", "<private@example.net"):
            with self.subTest(sender):
                outcome = self.reply(to, sender=sender)
                self.assertTrue(outcome[0].startswith("dropped:auth:"), outcome)
        self.assertEqual(self.reply(to, extra=[("Sender", "private@example.net, eve")]),
                         ["dropped:auth:sender"])
        accepted = ('"Last, First: x" <private@example.net>', "private@example.net", "<private@example.net>",
                    "=?utf-8?q?J=C3=BCrgen?= M. <private@Example.NET>")
        for index, sender in enumerate(accepted):
            with self.subTest(sender):
                self.assertEqual(self.reply(to, sender=sender, message_id=f"<ok{index}@mail.gmail.com>"), ["relayed"])

    def test_own_address_among_several_is_dropped(self):
        for sender in ("private@example.net, bob@example.org", "Reply <REPLY+abc@Example.com>"):
            with self.subTest(sender):
                self.assertEqual(self.run_message(inbound_message(sender=sender)), ["dropped:own-address"])
                self.assertEqual(self.run_message(inbound_message([("Reply-To", sender)])), ["dropped:own-address"])
        mixed = "you@example.com, x@y.example"
        self.assertEqual(self.run_message(inbound_message(sender=mixed)), ["notice:no-reply-to"])
        self.assertEqual(self.run_message(inbound_message([("Reply-To", mixed)])), ["dropped:own-address"])
        self.assertEqual([sent for sent in SES.sent if sent[0] != "relay@example.com"], [])
        self.assertFalse([key for key in TABLE.items if key.startswith("t#")])

    def test_no_token_is_ever_minted_for_an_own_address(self):
        forms = ("bob@example.org <private@example.net>", "bob@example.org; private@example.net",
                 "'private@example.net'", "x <private@example.net\x00>", "a@b.example;private@example.net",
                 "bob@example.org <YOU+x@example.com>", "private@example.net <bob@example.org>",
                 "private@ｅxample.net".encode("utf-8").decode("latin-1"), "<you@example.com", "relay@example.com.",
                 "private@example.net.", "private@example.net <private@example.net>", "private@example.net, ",
                 "private@example.net;", "x <private@example.net> y", "private@example.net (")
        allowed = ("forwarded", "dropped:own-address", "notice:no-sender", "notice:no-reply-to", "notice:malformed-headers")
        for index, sender in enumerate(forms):
            for extra, source in (((), "bob@example.org"), ((("Reply-To", sender),), "you@example.com"),
                                  ((("Reply-To", "visitor@example.org"),), "bob@example.org")):
                raw = inbound_message(extra, sender=sender, message_id=f"<own{index}@bob.example>")
                outcome = self.run_message(raw, source=source)[0]
                self.assertIn(outcome, allowed, sender)
                if "private@example.net" in sender.lower() and extra == (("Reply-To", "visitor@example.org"),):
                    self.assertNotEqual(outcome, "forwarded", sender)
                TABLE.items = {k: v for k, v in TABLE.items.items() if not k.startswith("d#")}
        peers = [item["peer"] for key, item in TABLE.items.items() if key.startswith("t#")]
        self.assertTrue(all(not relay.is_own(peer) for peer in peers), peers)
        self.assertTrue(all(sent[1] == ["private@example.net"] for sent in SES.sent))

    def test_own_address_in_a_display_name_or_comment_is_not_the_sender(self):
        for index, sender in enumerate(('"you@example.com via Forms" <forms@service.example>',
                                        "Bob (was you@example.com) <bob@example.org>",
                                        "prvs=0123abcd=you@example.com", "xprivate@example.net",
                                        "private@example.net.evil.example", "myreply@example.com")):
            with self.subTest(sender):
                raw = inbound_message(sender=sender, message_id=f"<dn{index}@bob.example>")
                self.assertEqual(self.run_message(raw), ["forwarded"])

    def test_huge_headers_are_handled_quickly(self):
        shapes = (",reply+" * 40000, "a," * 100000, '"' * 300000, "\\" * 300000, "." * 300000,
                  "a" * 200000 + " <bob@example.org>", "<a" * 200000)
        start = time.time()
        for index, value in enumerate(shapes):
            folded = "\r\n ".join(value[i:i + 900] for i in range(0, len(value), 900))
            for name in ("From", "Reply-To", "Cc", "References"):
                extra = [(name, folded)] if name != "From" else []
                sender = folded if name == "From" else "Bob <bob@example.org>"
                raw = inbound_message(extra, sender=sender, message_id=f"<big{index}{name}@bob.example>")
                self.assertIn(self.run_message(raw)[0], ("forwarded", "notice:no-sender", "dropped:own-address",
                                                         "notice:oversize-headers"))
            to = "reply+" + "a" * 26 + "@example.com"
            self.assertRegex(self.reply(to, sender=folded)[0], "^(dropped:auth:|notice:oversize-headers$)")
        self.assertLess(time.time() - start, 20)

    def test_body_split_uses_the_first_blank_line(self):
        body = b"one\n\r\n\r\ntwo\r\n\r\nthree\n"
        raw = inbound_message(body=b"").replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n\n" + body
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertTrue(SES.sent[0][2].endswith(b"\r\n\r\n" + body))
        self.assertEqual(relay.split_message(b"A: b\r\n\r\nx\n\ny"), (b"A: b", b"x\n\ny"))
        self.assertEqual(relay.split_message(b"A: b\n\r\nKey: x\r\n\r\ny"), (b"A: b", b"Key: x\r\n\r\ny"))
        self.assertEqual(relay.split_message(b"A: b\r\n\nx"), (b"A: b", b"x"))
        mixed = inbound_message(body=b"").replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n\r\nKey: body\r\n\r\nend\r\n"
        self.assertEqual(self.run_message(mixed), ["forwarded"])
        self.assertTrue(SES.sent[-1][2].endswith(b"\r\n\r\nKey: body\r\n\r\nend\r\n"))
        self.assertIsNone(self.parsed()["Key"])

    def test_message_without_a_body_is_forwarded_and_logged(self):
        raw = inbound_message(body=b"").rstrip(b"\r\n")
        with self.assertLogs(level="INFO") as logs:
            self.assertEqual(self.run_message(raw), ["forwarded"])
            self.assertEqual(self.run_message(raw, ["other@elsewhere.example"]), ["dropped:no-relay-recipient"])
        self.assertEqual(len([line for line in logs.output if '"outcome"' in line]), 2)
        self.assertTrue(SES.sent[0][2].endswith(b"\r\n\r\n"))

    def test_over_long_ids_do_not_lose_mail(self):
        long_id = "<" + "a" * 3000 + "@bob.example>"
        raw = inbound_message([("References", f"<c0@bob.example> {long_id}"), ("In-Reply-To", long_id)],
                              message_id=long_id)
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertEqual((self.header("References"), self.header("In-Reply-To")), (relay.wrap("c0@bob.example"), ""))
        self.assertTrue(all(len(key) < 1024 for key in TABLE.items))
        to = f"reply+{self.token()}@example.com"
        self.assertEqual(self.reply(to, message_id=long_id), ["notice:no-message-id"])

    def test_comments_and_mixed_signers_cannot_hide_an_entry(self):
        hidden = AUTH.replace("helo=mail-vs1-f47.google.com; dkim=pass header.i=@example.net;",
                              "helo=x; dkim=pass header.i=@example.net; a=b(; dkim=pass header.i=x)y@evil.example;")
        cases = (hidden, "(c) " + AUTH, AUTH.replace("amazonses.com;", "amazonses.com (c);"),
                 AUTH.replace("header.i=@example.net", "header.d=evil.example header.i=@example.net"),
                 AUTH.replace("dkim=pass header.i=@example.net", "dkim=pass"),
                 AUTH.replace("helo=mail-vs1-f47.google.com", "helo=x(y)"))
        for value in cases:
            with self.subTest(value):
                self.assertNotEqual(value, AUTH)
                self.assertFalse(relay.aligned_dkim(value))
        self.assertTrue(relay.aligned_dkim(AUTH))
        self.assertTrue(relay.aligned_dkim(AUTH.replace(" (spfCheck: 209.85.217.47 is neither permitted nor denied "
                                                        "by domain of example.net)", "")))

    def test_failed_notice_is_retried_and_a_sending_pause_consumes_nothing(self):
        event = self.event(inbound_message(), ["you@example.com"], length=relay.MAX_BYTES + 1)
        SES.errors.append(FakeError("ThrottlingException", 400))
        with self.assertRaises(FakeError):
            relay.handler(event, None)
        self.assertEqual(self.notices(), [])
        self.assertEqual(relay.handler(event, None)["results"], ["notice:oversize"])
        self.assertEqual(len(self.notices()), 1)
        for code in ("AccountSuspendedException", "SendingPausedException"):
            paused = self.event(inbound_message(message_id=f"<{code}@bob.example>"), ["you@example.com"])
            SES.errors.append(FakeError(code, 400))
            with self.assertRaises(FakeError):
                relay.handler(paused, None)
            self.assertEqual(relay.handler(paused, None)["results"], ["forwarded"])
        self.assertEqual(len(self.notices()), 1)

    def test_header_guard_sees_encoded_forms(self):
        to = self.first_contact()
        encoded = b"Subject: =?utf-8?b?d3JpdGUgdG8gcHJpdmF0ZUBleGFtcGxlLm5ldA==?="
        cases = (
            reply_message(to).replace(b"Subject: Re: Hi", encoded),
            reply_message(to, extra=[("Content-Disposition",
                                      "attachment; filename*=utf-8''private%40example.net.txt")]),
        )
        for raw in cases:
            self.assertEqual(self.run_message(raw, [to], source="private@example.net"), ["notice:header-guard"])
            TABLE.items = {k: v for k, v in TABLE.items.items() if not k.startswith("d#notice")}
        self.assertFalse([sent for sent in SES.sent if sent[0] == "you@example.com"])

    def test_notices_are_sent_once_per_event(self):
        event = self.event(inbound_message(), ["you@example.com"], length=relay.MAX_BYTES + 1)
        self.assertEqual(relay.handler(event, None)["results"], ["notice:oversize"])
        self.assertEqual(relay.handler(event, None)["results"], ["notice:oversize"])
        self.assertEqual(len(self.notices()), 1)

    def test_access_denied_is_retried_not_consumed(self):
        event = self.event(inbound_message(), ["you@example.com"])
        SES.errors.append(FakeError("AccessDeniedException", 403))
        with self.assertRaises(FakeError):
            relay.handler(event, None)
        self.assertFalse([key for key in TABLE.items if key.startswith("d#")])
        self.assertEqual(relay.handler(event, None)["results"], ["forwarded"])

    def test_rejected_message_is_retried_until_its_notice_is_sent(self):
        event = self.event(inbound_message(), ["you@example.com"])
        SES.errors.extend([FakeError("MessageRejected", 400), FakeError("ThrottlingException", 400)])
        with self.assertRaises(FakeError):
            relay.handler(event, None)
        self.assertFalse([key for key in TABLE.items if key.startswith("d#")])
        SES.errors.append(FakeError("MessageRejected", 400))
        self.assertEqual(relay.handler(event, None)["results"], ["notice:rejected"])
        self.assertEqual(self.notices(), ["Relay notice: rejected"])
        self.assertEqual(relay.handler(event, None)["results"], ["duplicate"])
        to = self.first_contact()
        SES.errors.extend([FakeError("MessageRejected", 400), Exception("connection reset")])
        with self.assertRaises(Exception):
            self.reply(to)
        SES.errors.append(FakeError("MessageRejected", 400))
        self.assertEqual(self.reply(to), ["notice:rejected"])
        self.assertEqual(len(self.notices()), 2)

    def test_hardening_edge_cases(self):
        self.assertFalse(relay.aligned_dkim(AUTH.replace("header.i=@example.net;",
                                                         "header.i=@example.net Header.D=evil.example;")))
        self.assertTrue(relay.aligned_dkim(AUTH.replace("header.i=@example.net;", "Header.I=@Example.NET;")))
        for value in (AUTH.replace("dkim=pass header.i=@example.net;",
                                   "dkim=pass header.i=@example.net; x=y dkim=pass header.i=@evil.example;"),
                      AUTH.replace("dkim=pass", "dmarc=fail header.from=example.net; dkim=pass"),
                      AUTH.replace("helo=mail-vs1-f47.google.com", "helo=x DKIM=pass")):
            self.assertFalse(relay.aligned_dkim(value), value)
        for code, status in (("ExpiredTokenException", 400), ("RequestTimeout", 408), ("InvalidSignatureException", 403)):
            self.assertFalse(relay.permanent(FakeError(code, status)), code)
        self.assertTrue(relay.permanent(FakeError("MessageRejected", 400)))
        wide = "<" + "\U0001F600" * 300 + "@bob.example>"
        self.assertEqual(relay.translate_in({"references": wide, "in-reply-to": wide, "message-id": wide}), ([], None))
        to = self.first_contact()
        cases = (
            reply_message(to, extra=[("Content-Description", "x; a*=utf-8''private%40example.net")]),
            reply_message(to, extra=[("Content-Description", "note; n==?utf-8?b?cHJpdmF0ZUBleGFtcGxlLm5ldA==?=")]),
            reply_message(to, extra=[("Message-ID", "<second@mail.gmail.com>")]),
            reply_message(to, message_id="<a@mail.gmail.com> <b@mail.gmail.com>"),
            reply_message(to, message_id="<caf\u00e9@mail.gmail.com>".encode("utf-8").decode("latin-1")),
        )
        expected = ["notice:header-guard", "notice:header-guard"] + ["notice:no-message-id"] * 3
        for raw, outcome in zip(cases, expected):
            self.assertEqual(self.run_message(raw, [to], source="private@example.net"), [outcome])
            TABLE.items = {k: v for k, v in TABLE.items.items() if not k.startswith("d#notice")}
        mail = {"messageId": "x", "source": "bob@example.org", "commonHeaders": {"subject": "bad \udc80 subject"}}
        relay.notify("oversize", mail)
        self.assertEqual(self.notices()[-1], "Relay notice: oversize")

    def test_repeated_and_nested_headers_cannot_stall_or_crash(self):
        start = time.time()
        for index, fill in enumerate(("\\", ".", '"')):
            raw = inbound_message([("From", fill * 8100)] * 30, message_id=f"<rep{index}@bob.example>")
            self.assertEqual(self.run_message(raw), ["forwarded"])
            self.assertIn("bob at example.org", self.header("From"))
            raw = inbound_message([("From", fill * 8100)] * 60, message_id=f"<many{index}@bob.example>")
            self.assertEqual(self.run_message(raw), ["notice:oversize-headers"])
        nested = b"text/plain; a=" + b"(" * 600
        raw = inbound_message(message_id="<nest@bob.example>").replace(b"text/plain; charset=utf-8", nested)
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertIn(nested, SES.sent[-1][2])
        to = f"reply+{self.token()}@example.com"
        raw = reply_message(to).replace(b"text/plain; charset=utf-8", nested)
        self.assertIn(self.run_message(raw, [to], source="private@example.net")[0], ("notice:header-guard", "relayed"))
        self.assertLess(time.time() - start, 2)

    def test_field_limit_is_measured_on_the_wire(self):
        def cc(wire):  # one line on the wire: "Cc: " + value + CRLF
            return "carol@example.org (" + "x" * (wire - len("Cc: carol@example.org ()") - 2) + ")"

        self.assertEqual(self.run_message(inbound_message([("Cc", cc(relay.MAX_FIELD))])), ["forwarded"])
        self.assertEqual(self.parsed()["X-Relay-Original-Cc"], "carol@example.org")
        over = inbound_message([("Cc", cc(relay.MAX_FIELD + 1))], message_id="<over@bob.example>")
        self.assertEqual(self.run_message(over), ["forwarded"])
        self.assertIsNone(self.parsed()["X-Relay-Original-Cc"])
        folded = "carol@example.org,\r\n " + ",\r\n ".join(f"c{i}@example.org" for i in range(500))
        self.assertGreater(len(folded), relay.MAX_FIELD)
        self.run_message(inbound_message([("Cc", folded)], message_id="<fold@bob.example>"))
        self.assertIsNone(self.parsed()["X-Relay-Original-Cc"])
        twice = inbound_message([("Cc", cc(relay.MAX_FIELD + 1)), ("Cc", "dave@example.org")], message_id="<two@bob.example>")
        self.run_message(twice)
        self.assertIsNone(self.parsed()["X-Relay-Original-Cc"])

    def test_many_small_headers_get_a_notice(self):
        raw = b"a:\n" * 300000 + inbound_message()
        self.assertEqual(self.run_message(raw), ["notice:oversize-headers"])
        self.assertEqual(self.notices(), ["Relay notice: oversize-headers"])
        self.assertEqual(len(SES.sent), 1)
        under = b"a:\r\n" * 50000 + inbound_message(message_id="<small@bob.example>")
        self.assertEqual(self.run_message(under), ["forwarded"])

    def test_display_names_are_decoded_then_cut_before_the_address(self):
        def shown():
            return str(email.header.make_header(email.header.decode_header(self.header("From"))))

        long_name = "J\u00fcrgenM\u00fcller" * 10
        encoded = email.header.Header(long_name, "utf-8").encode().replace("\n", "\r\n")
        self.assertEqual(self.run_message(inbound_message(sender=f"{encoded} <bob@example.org>")), ["forwarded"])
        self.assertIn(f'{long_name[:70]} (bob at example.org)', shown())
        self.assertNotIn(long_name[:71], shown())
        raw = inbound_message(sender="N" * 90 + " <dave@example.org>", message_id="<long@bob.example>")
        self.assertEqual(self.run_message(raw), ["forwarded"])
        self.assertIn("N" * 70 + " (dave at example.org)", shown())
        head = SES.sent[-1][2].split(b"\r\n\r\n", 1)[0]
        self.assertTrue(all(len(line) < 1000 for line in head.split(b"\r\n")))

    def test_header_guard_split_parameter_forms_and_size(self):
        to = self.first_contact()
        forms = (
            "attachment; filename*0*=utf-8''priv; filename*1*=ate%40example.net.txt",
            'attachment; filename*0="private@exam"; filename*1="ple.net.txt"',
            'attachment; filename="private\\@example.net"',
        )
        for index, form in enumerate(forms):
            raw = reply_message(to, extra=[("Content-Disposition", form)], message_id=f"<g{index}@mail.gmail.com>")
            self.assertEqual(self.run_message(raw, [to], source="private@example.net"), ["notice:header-guard"], form)
        big = reply_message(to, extra=[("Content-Description", "x" * 20000)], message_id="<big@mail.gmail.com>")
        self.assertEqual(self.run_message(big, [to], source="private@example.net"), ["notice:header-too-large"])
        self.assertFalse([sent for sent in SES.sent if sent[0] == "you@example.com"])

    def test_refusal_whose_notice_is_rejected_raises(self):
        event = self.event(inbound_message(), ["you@example.com"], length=relay.MAX_BYTES + 1)
        for _ in range(3):
            SES.errors.append(FakeError("MessageRejected", 400))
            with self.assertRaises(RuntimeError):
                relay.handler(event, None)
            self.assertFalse([key for key in TABLE.items if key.startswith("d#")])
        self.assertEqual(relay.handler(event, None)["results"], ["notice:oversize"])
        self.first_contact()
        SES.errors.append(FakeError("MessageRejected", 400))
        with self.assertRaises(RuntimeError):
            self.reply("reply+" + "a" * 26 + "@example.com")
        self.assertEqual(self.notices(), ["Relay notice: oversize"])

    def test_form_mail_from_the_alias_with_an_outside_reply_to(self):
        for index, sender in enumerate(("Site <you@example.com>", "you+form@example.com")):
            raw = inbound_message([("Reply-To", "Visitor <visitor@example.org>")], sender=sender,
                                  message_id=f"<form{index}@site.example>")
            self.assertEqual(self.run_message(raw, source="you@example.com"), ["forwarded"])
            self.assertIn("visitor at example.org", self.header("From"))
            self.assertNotIn("you at example.com", self.header("From"))
        self.assertEqual(TABLE.items["t#" + self.token(peer="visitor@example.org")]["peer"], "visitor@example.org")
        dropped = (
            ("you@example.com", "you@example.com", "you@example.com"),
            ("you@example.com", "private@example.net", "you@example.com"),
            ("you@example.com", "reply+abc@example.com", "you@example.com"),
            ("you@example.com", "visitor@example.org, you@example.com", "you@example.com"),
            ("private@example.net", "visitor@example.org", "bob@example.org"),
            ("relay@example.com", "visitor@example.org", "bob@example.org"),
            ("you@example.com", "visitor@example.org", "private@example.net"),
            ("you@example.com", "visitor@example.org", "reply+abc@example.com"),
        )
        sent = len(SES.sent)
        for sender, reply_to, source in dropped:
            with self.subTest((sender, reply_to, source)):
                raw = inbound_message([("Reply-To", reply_to)], sender=sender, message_id="<drop@site.example>")
                self.assertEqual(self.run_message(raw, source=source), ["dropped:own-address"])
        self.assertEqual(len(SES.sent), sent)
        self.assertEqual(len([key for key in TABLE.items if key.startswith("t#")]), 1)

    def test_sender_written_text_cannot_misroute_or_crash(self):
        cases = (
            ("zqew" + "9" * 4400 + "qz <bob@example.org>", "bob@example.org"),
            ("zqew0qz =?utf-8?q?Bob?= <bob@example.org>", "bob@example.org"),
            ("=?utf-8?q?Bob?= <zqew0qz@example.org>", "zqew0qz@example.org"),
            ("=?utf-7?q?+2AA-?= <bob@example.org>", "bob@example.org"),
            ("=?unicode_escape?q?=5Cud800?= <bob@example.org>", "bob@example.org"),
        )
        for index, (sender, peer) in enumerate(cases):
            with self.subTest(sender[:40]):
                raw = inbound_message(sender=sender, message_id=f"<w{index}@bob.example>")
                self.assertEqual(self.run_message(raw, source="envelope@example.org"), ["forwarded"])
                self.assertEqual(TABLE.items["t#" + self.token(peer=peer)]["peer"], peer)
                SES.sent[-1][2].split(b"\r\n\r\n", 1)[0].decode("ascii")
        name = str(email.header.make_header(email.header.decode_header(self.header("From", 1))))
        self.assertEqual(name.count("Bob"), 1)

    def test_encoded_name_with_a_comma_falls_back_to_the_envelope_sender(self):
        raw = inbound_message(sender="=?utf-8?q?Doe,_J=C3=BCrgen?= <carol@example.org>")
        self.assertEqual(self.run_message(raw, source="carol@example.org"), ["forwarded"])
        self.assertEqual(TABLE.items["t#" + self.token(peer="carol@example.org")]["peer"], "carol@example.org")

    def test_only_a_real_single_from_header_names_the_sender(self):
        boss = b"Boss <ceo@bank.example>"
        real = b"From: Eve <eve@evil.example>"
        base = inbound_message(sender="Eve <eve@evil.example>")
        forged = (
            base.replace(real, b"Fr\xffom: " + boss + b"\r\n" + real),
            base.replace(real, b"From\xc2\xa0: " + boss + b"\r\n" + real),
        )
        for index, raw in enumerate(forged):
            with self.subTest(index):
                raw = raw.replace(b"<c1@bob.example>", f"<forged{index}@bob.example>".encode())
                self.assertEqual(self.run_message(raw, source="eve@evil.example"), ["forwarded"])
                self.assertIn("(eve at evil.example)", self.header("From"))
                self.assertNotIn("p#you@example.com#ceo@bank.example", TABLE.items)
        for index, second in enumerate(("Boss <ceo@bank.example>", "private@example.net", "reply+abc@example.com")):
            with self.subTest(second):
                raw = inbound_message([("From", second)], sender="Eve <eve@evil.example>", message_id=f"<two{index}@bob.example>")
                self.assertEqual(self.run_message(raw, source="eve@evil.example"), ["forwarded"])
                self.assertEqual(self.header("From").split(" <")[0], '"eve at evil.example"')
                raw = inbound_message([("Reply-To", "a@b.example"), ("Reply-To", second)], message_id=f"<rt{index}@bob.example>")
                self.assertEqual(self.run_message(raw), ["forwarded"])
                self.assertIn("(bob at example.org)", self.header("From"))
        self.assertTrue(all(not relay.is_own(item["peer"]) for key, item in TABLE.items.items() if key.startswith("t#")))

    def test_header_guard_reassembles_what_lenient_clients_would(self):
        to = self.first_contact()
        forms = (
            ("Content-Disposition", "attachment; filename=\"a.txt\"; filename*0*=utf-8''priv; filename*1*=ate%40example.net"),
            ("Content-Disposition", "attachment; FILENAME*0=\"private@exam\"; filename*1=\"ple.net\""),
            ("Content-Disposition", "attachment; filename*0 = \"private@exam\"; filename*1 = \"ple.net\""),
            ("Content-Disposition", "attachment; filename*0=\"private@exam\"; filename*2=\"ple.net\""),
            ("Content-Description", "x; a*0=\"private@exam\"; a*1=\"ple.net\""),
            ("Content-Description", "x; a*0*=utf-8''priv; a*1*=ate%40example.net"),
            ("Content-ID", "<x> (private\\@example.net)"),
            ("Content-Language", "en; n=\"private\\@example.net\""),
        )
        for index, (name, value) in enumerate(forms):
            with self.subTest(value):
                raw = reply_message(to, extra=[(name, value)], message_id=f"<s{index}@mail.gmail.com>")
                self.assertEqual(self.run_message(raw, [to], source="private@example.net"), ["notice:header-guard"])
        harmless = reply_message(to, extra=[("Content-Disposition", "attachment; filename*0=\"report\"; filename*1=\".pdf\"")],
                                 message_id="<ok@mail.gmail.com>")
        self.assertEqual(self.run_message(harmless, [to], source="private@example.net"), ["relayed"])

    def test_header_guard_parses_once_per_message(self):
        slow = "text/plain" + ";" * 15000
        recipients = [f"you+p{index}=example.org@example.com" for index in range(40)]
        raw = reply_message(", ".join(recipients)).replace(b"text/plain; charset=utf-8", slow.encode())
        start = time.time()
        results = self.run_message(raw, recipients, source="private@example.net")
        self.assertEqual(set(results), {"composed"})
        self.assertLess(time.time() - start, 8)

    def test_bare_cr_and_control_characters_are_refused_with_a_notice(self):
        base = inbound_message()
        hidden = b"X-A: a\rReply-To: attacker@evil.example\rDisposition-Notification-To: attacker@evil.example"
        cases = (
            base.replace(b"Subject: Hi", hidden + b"\r\nSubject: Hi"),
            base.replace(b"Subject: Hi", b"X-A: a\rX-Relay-Hop: v1\r\nSubject: Hi"),
            base.replace(b"From: Bob", b"From\x1f: Boss <ceo@bank.example>\r\nFrom: Bob"),
            base.replace(b"From: Bob", b"\x0bFrom: Boss <ceo@bank.example>\r\nFrom: Bob"),
            base.replace(b"Subject: Hi", b"Subject: Hi\x00"),
            base.replace(b"Subject: Hi", b"Subject: Hi\x7f"),
        )
        for index, raw in enumerate(cases):
            with self.subTest(index):
                self.assertEqual(self.run_message(raw), ["notice:malformed-headers"])
        self.assertEqual(self.notices(), ["Relay notice: malformed-headers"] * len(cases))
        self.assertFalse([key for key in TABLE.items if key.startswith(("t#", "p#"))])
        tabs = base.replace(b"Subject: Hi", b"Subject: Hi\r\n\tthere") + b"\rbody with a bare CR and \x00 is untouched\r\n"
        self.assertEqual(self.run_message(tabs), ["forwarded"])
        self.assertTrue(SES.sent[-1][2].endswith(b"\rbody with a bare CR and \x00 is untouched\r\n"))
        to = f"reply+{self.token()}@example.com"
        raw = reply_message(to).replace(b"Subject: Re: Hi", b"Subject: Re: Hi\x01")
        self.assertEqual(self.run_message(raw, [to], source="private@example.net"), ["notice:malformed-headers"])

    def test_raw_utf8_names_and_form_mail_without_a_reply_to(self):
        raw = inbound_message().replace(b"From: Bob", "From: Jürgen Müller".encode("utf-8"))
        self.assertEqual(self.run_message(raw), ["forwarded"])
        name = str(email.header.make_header(email.header.decode_header(self.header("From"))))
        self.assertIn("Jürgen Müller (bob at example.org)", name)
        SES.sent[-1][2].split(b"\r\n\r\n", 1)[0].decode("ascii")
        for index, extra in enumerate(([], [("Reply-To", "a@b.example"), ("Reply-To", "c@d.example")],
                                       [("Reply-To", "=?utf-8?q?Doe,_J?= <v@example.org>")])):
            with self.subTest(index):
                raw = inbound_message(extra, sender="Site <you@example.com>", message_id=f"<nr{index}@site.example>")
                self.assertEqual(self.run_message(raw, source="you@example.com"), ["notice:no-reply-to"])
        self.assertEqual(self.notices(), ["Relay notice: no-reply-to"] * 3)
        mail = {"messageId": "y", "source": "bob@example.org", "commonHeaders": None}
        relay.notify("oversize", mail)
        self.assertEqual(self.notices()[-1], "Relay notice: oversize")

    def test_encoded_words_are_checked_once_for_many_recipients(self):
        subject = "=??q?\\" * 2700
        recipients = [f"you+q{index}=example.org@example.com" for index in range(40)]
        raw = reply_message(", ".join(recipients)).replace(b"Subject: Re: Hi", b"Subject: " + subject.encode())
        start = time.time()
        results = self.run_message(raw, recipients, source="private@example.net")
        self.assertEqual(len(set(results)), 1)
        self.assertLess(time.time() - start, 5)

    def test_forward_name_never_holds_an_address_or_an_encoded_word(self):
        def twice(value):  # what a client shows if it decodes encoded words, even inside quotes
            once = str(email.header.make_header(email.header.decode_header(value)))
            return str(email.header.make_header(email.header.decode_header(once.strip('"'))))

        cases = (
            ("writer@mail.example", "writer at mail.example"),
            ('"bob@example.org" <bob@example.org>', "bob at example.org"),
            ('"BOB@Example.ORG" <bob@example.org>', "bob at example.org"),
            ('"ceo@bank.example" <eve@evil.example>', "ceo at bank.example (eve at evil.example)"),
            ("Boss ceo\uff20bank.example <eve@evil.example>", "Boss ceo at bank.example (eve at evil.example)"),
            ("=?utf-8?q?=3D=3Futf-8=3Fq=3Fceo=3D40bank.example=3F=3D?= <eve@evil.example>", "(eve at evil.example)"),
            ("<=?utf-8?q?ceo=40bank.example?=@evil.example>", " at evil.example"),
            ('"' + "@" * 70 + '" <bob@example.org>', "(bob at example.org)"),
            ('"=\\?utf-8?q?ceo=40bank.example?=" <eve@evil.example>', "(eve at evil.example)"),
            ("=?utf-8?q?=3D=01=3Futf-8=3Fq=3Fceo=3D40bank.example=3F=3D?= <eve@evil.example>", "(eve at evil.example)"),
            ("=?utf-8?q?a=00b=08c=7Fd=1B?= <bob@example.org>", "(bob at example.org)"),
            ('"=\\"?utf-8?q?ceo=40bank.example?=" <eve@evil.example>', "(eve at evil.example)"),
            ('"Bob \\"X\\"" <bob@example.org>', "Bob X (bob at example.org)"),
            ("=?utf-8?q?=3D=C2=80=3Futf-8=3Fq=3Fceo=3D40bank.example=3F=3D?= <eve@evil.example>", "(eve at evil.example)"),
            ("=?utf-8?b?" + __import__("base64").b64encode(("\U0001F600" * 70).encode()).decode() + "?= <"
             + "=?" * 30 + "x@" + ".".join(["d" * 60] * 3) + ".example>", " at " + ".".join(["d" * 60] * 3) + ".example"),
        )
        for index, (sender, expected) in enumerate(cases):
            with self.subTest(sender[:40]):
                raw = inbound_message(sender=sender, message_id=f"<name{index}@bob.example>")
                self.assertEqual(self.run_message(raw, source="envelope@example.org"), ["forwarded"])
                header = self.header("From")
                name, address = header.rsplit(" <", 1)
                self.assertRegex(address, r"^reply\+[a-z2-7]{26}@example\.com>$")
                shown = twice(name)
                self.assertIn(expected, shown)
                self.assertNotIn("@", shown)
                self.assertNotIn("=?", shown)
                line = [l for l in SES.sent[-1][2].split(b"\r\n\r\n")[0].split(b"\r\n") if l.startswith(b"From:")][0]
                head = SES.sent[-1][2].split(b"\r\n\r\n")[0]
                start = head.index(b"From:")
                line = head[start:head.index(b"\r\nTo:", start)]  # the From header with its folded lines
                self.assertFalse(re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\\]", line), line)
                for reader in (r"[\x00-\x1f\x7f-\x9f\\]", r'[\x00-\x1f\x7f-\x9f\\"]'):
                    lenient = re.sub(reader, "", name)  # a reader that drops what it cannot show
                    self.assertNotIn("@", twice(lenient))
                self.assertTrue(all(len(l) < 998 for l in head.split(b"\r\n")))
                if b"=?utf-8?" in line:
                    self.assertTrue(all(len(l) <= 76 for l in line.split(b"\r\n")), line)
                    self.assertTrue(all(len(word) <= 75 for word in re.findall(rb"=\?utf-8\?[bq]\?[^?]*\?=", line)), line)
        exact = self.header("From", 0), self.header("From", 1)
        self.assertEqual(exact[0].rsplit(" <", 1)[0], '"writer at mail.example"')
        self.assertEqual(exact[1].rsplit(" <", 1)[0], '"bob at example.org"')
        peers = sorted(item["peer"] for key, item in TABLE.items.items() if key.startswith("t#"))
        self.assertIn("writer@mail.example", peers)
        self.assertIn("eve@evil.example", peers)

    def test_send_call_carries_the_from_header_with_its_name(self):
        def header_value(data):  # the unfolded From header of a sent message
            lines = data.split(b"\r\n\r\n", 1)[0].decode("ascii").split("\r\n")
            start = [i for i, line in enumerate(lines) if line.lower().startswith("from:")][0]
            parts = [lines[start][5:]]
            for line in lines[start + 1:]:
                if not line.startswith((" ", "\t")):
                    break
                parts.append(line)
            return " ".join(part.strip() for part in parts)

        long_name = "JürgenMüller" * 10
        encoded = email.header.Header(long_name, "utf-8").encode().replace("\n", "\r\n")
        senders = ("Bob <bob@example.org>", "carol@example.org", f"{encoded} <dave@example.org>")
        for index, sender in enumerate(senders):
            self.assertEqual(self.run_message(inbound_message(sender=sender, message_id=f"<p{index}@bob.example>")),
                             ["forwarded"])
            param = SES.params[-1]
            self.assertEqual(param, header_value(SES.sent[-1][2]))
            self.assertNotIn("\n", param)
            param.encode("ascii")
            self.assertRegex(email.utils.parseaddr(param)[1], r"^reply\+[a-z2-7]{26}@example\.com$")
        self.assertEqual(SES.params[0].rsplit(" <", 1)[0], '"Bob (bob at example.org)"')
        self.assertEqual(SES.params[1].rsplit(" <", 1)[0], '"carol at example.org"')
        shown = str(email.header.make_header(email.header.decode_header(SES.params[2].rsplit(" <", 1)[0])))
        self.assertEqual(shown, f"{long_name[:70]} (dave at example.org)")
        to = f"reply+{self.token()}@example.com"
        self.assertEqual(self.reply(to), ["relayed"])
        self.assertEqual(SES.params[-1], "You <you@example.com>")
        self.assertEqual(SES.params[-1], header_value(SES.sent[-1][2]))
        self.run_message(inbound_message(message_id="<big@bob.example>"), length=relay.MAX_BYTES + 1)
        self.assertEqual(email.utils.parseaddr(SES.params[-1]), ("Mail relay", "relay@example.com"))
        self.assertEqual(SES.params[-1], header_value(SES.sent[-1][2]))

    def test_every_outcome_the_function_can_log_has_a_readme_row(self):
        outcomes = {
            "forwarded", "relayed", "composed", "duplicate", "quarantined", "dry-run:reply", "dry-run:compose",
            "dropped:own-output", "dropped:own-address", "dropped:unknown-recipient", "dropped:no-relay-recipient",
        }
        outcomes |= {"dropped:auth:" + reason for reason in (
            "scan", "verdict", "dkim-alignment", "duplicate-header", "from", "sender", "envelope-sender",
            "recipient-not-in-header")}
        outcomes |= {"notice:" + reason for reason in (
            "oversize", "oversize-headers", "malformed-headers", "rejected", "no-sender", "no-reply-to",
            "unknown-token", "bad-compose-target", "own-address", "header-guard", "header-too-large",
            "no-message-id", "auto-submitted", "precedence", "list", "report")}
        source = (ROOT / "src" / "relay.py").read_text()

        def between(start, end):
            return source.split(start, 1)[1].split(end, 1)[0]

        # The same set, derived from the source, so a new outcome cannot be added without a row.
        derived = set(re.findall(r'"((?:dropped|notice|dry-run):[a-z:-]*[a-z])"', source))
        derived |= set(re.findall(r'return "(forwarded|quarantined|duplicate)"', source))
        derived |= {"relayed", "composed"} & set(re.findall(r'"(relayed|composed)"', source))
        derived |= {"dry-run:" + leg for leg in re.findall(r'outbound\("(reply|compose)"', source)}
        derived |= {"dropped:auth:" + reason for reason in
                    re.findall(r'return "([a-z-]+)"', between("def operator_auth", "def outbound_refusal"))}
        derived |= {"notice:" + reason for reason in
                    re.findall(r'return "([a-z-]+)"', between("def outbound_refusal", "def inbound_quarantine"))}
        derived |= {"notice:" + reason for reason in re.findall(r'(?:refuse|notify)\("([a-z-]+)"', source)}
        derived |= {"notice:" + reason for reason in re.findall(r'"(oversize-headers|malformed-headers)"', source)}
        self.assertEqual(derived, outcomes)
        # Every string the routing functions can return, so an outcome of a new shape cannot slip in.
        literals = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.FunctionDef) and node.name in ("inbound", "outbound", "route", "process", "refuse"):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Return) and inner.value is not None:
                        literals |= {c.value for c in ast.walk(inner.value)
                                     if isinstance(c, ast.Constant) and isinstance(c.value, str)}
        legs, keys, prefixes = {"inbound", "reply", "compose", "none"}, {"tok", "out"}, {"notice:", "dry-run:", "dropped:auth:"}
        refusals = {o.split(":", 1)[1] for o in outcomes if o.startswith("notice:")}
        self.assertEqual(sorted(literals - legs - keys - prefixes - outcomes - refusals), [])
        readme = (ROOT / "README.md").read_text()
        self.assertEqual(sorted(o for o in outcomes if f"| `{o}` |" not in readme), [])
        for warning in ("send rejected", "notice not sent", "anchor not stored"):
            self.assertIn(warning, source)
            self.assertIn(warning, readme)

    def test_rendered_template(self):
        template = (ROOT / "relay.yml").read_text()
        source = (ROOT / "src" / "relay.py").read_text()
        rendered = render.render(template, source)
        self.assertNotIn(render.PLACEHOLDER, rendered)
        self.assertLess(len(rendered.encode()), render.MAX_TEMPLATE_BYTES)
        block = rendered.split("        ZipFile: |\n", 1)[1].split("\n  SesInvokePermission:", 1)[0]
        dedented = "\n".join(line[10:] if line else "" for line in block.rstrip("\n").split("\n"))
        self.assertEqual(dedented.rstrip("\n"), source.rstrip("\n"))
        compile(dedented, "index.py", "exec")
        flat = re.sub(r"\s+", " ", rendered)
        for expected in (
            "RuleSetName: !Ref RuleSetName After: !If [HasAfter, !Ref AfterRule, !Ref AWS::NoValue] Rule: Name: relay-inbound",
            "HasAfter: !Not [!Equals [!Ref AfterRule, '']]",
            "Recipients: - !Ref Alias - !Sub reply@${Domain} ScanEnabled: true",
            "- StopAction: Scope: RuleSet",
            "DependsOn: - MailBucketPolicy - SesInvokePermission",
            "DependsOn: RelayLogGroup",
            "StringLike: ses:FromAddress: - !Sub reply+*@${Domain} - !Sub relay@${Domain} "
            "ForAllValues:StringEquals: ses:Recipients: - !Ref PrivateAddress",
            "StringEquals: ses:FromAddress: !Ref Alias",
            "OUTBOUND: !Ref OutboundEnabled",
        ):
            self.assertIn(expected, flat)
        self.assertEqual(flat.count("Action: ses:SendRawEmail"), 2)
        # Both SES grants follow the rule set parameter, and no account-specific name remains.
        self.assertEqual(flat.count("receipt-rule-set/${RuleSetName}:receipt-rule/relay-inbound"), 2)
        self.assertEqual(flat.count("receipt-rule-set/"), 2)
        self.assertEqual(flat.count("default-rule-set"), 1)
        self.assertIn("RuleSetName: Type: String Default: default-rule-set", flat)
        self.assertIn("AfterRule: Type: String Default: ''", flat)
        self.assertNotIn("SetActiveReceiptRuleSet", rendered)
        self.assertNotIn("AWS::SES::ReceiptRuleSet", rendered)


if __name__ == "__main__":
    unittest.main()
