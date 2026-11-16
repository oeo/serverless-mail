# Serverless reverse-alias mail relay on AWS: implementation plan

Status: built, unit tested, and deployed once, by its author, for one alias on a domain SES already received for, with replies switched on. `README.md` is the setup guide. Sections 10 to 13 and 16 to 18 describe the original design and that first deployment, with example names standing in for the account's real rules and domains; section 23 lists where the code and the template now differ. A real round trip worked: a forward, a reply relayed under the alias, and a second message threaded. The outside forgery test (live test L1) was not run before replies were switched on; the owner accepted that. Section 23 lists where the build departs from this document.

This document describes how to build a mail relay on Amazon SES, AWS Lambda, Amazon S3, and Amazon DynamoDB. The relay lets mail sent to an address at one of your domains land in an ordinary private inbox (Gmail, iCloud, or any other provider), and lets you reply from that inbox without the correspondent ever seeing the private address or which provider hosts it. Your mail client needs no "send mail as" or SMTP setup.

Throughout this document:

| Placeholder | Meaning |
|---|---|
| `example.com` | A relay domain you own (deploy-time parameter) |
| `you@example.com` | An alias on the relay domain that correspondents write to |
| `private@example.net` | Your private inbox (deploy-time parameter, called `PRIVATE_ADDRESS`) |
| `bob@example.org` | A correspondent |
| `123456789012` | The AWS account id |

Claims marked **Unverified** were not confirmed from AWS documentation or a test. Each says what would settle it. Section 20 lists them all.

## 0. Precondition you must check before deploying

**Your private inbox's provider must DKIM-sign your outgoing mail with a domain aligned to the inbox's own domain.** The reply leg accepts a reply only when SES reports a passing DKIM signature whose domain is the private address's domain or a subdomain of it (section 8). If the provider signs with some other domain, every reply you send is refused, silently, by design.

Example of a setup that fails: a Google Workspace domain that never turned on its own DKIM key. Workspace then signs with a Google-owned default domain (`*.gappssmtp.com`), not with your domain. A sample from such a domain, received by SES in this account, showed `dkim=pass` only for the Google domain, `spf=none`, and `dmarc=fail`. Consumer Gmail (`@gmail.com`) and iCloud (`@icloud.com`) sign with their own domains (**Unverified** for each provider; the check below settles it).

How to check, before deploying anything:

1. Send a message from the private inbox to any mailbox where you can view the full source (for example a second account at another provider).
2. Open "show original" or "view source" and find the `DKIM-Signature` header. Its `d=` tag must equal the private address's domain (for `private@example.net`, `d=example.net`) or a subdomain of it.
3. Find the receiving server's `Authentication-Results` header and confirm `dkim=pass` for that same domain.

If the `d=` domain differs, either turn on the provider's custom-domain DKIM for that domain (in Google Workspace: Admin console, Apps, Gmail, Authenticate email) and repeat the check, or use a different private inbox. After deploying, the dry-run switch in section 16 lets you confirm this against SES itself before any reply is relayed.

## 1. Requirements and non-goals

### Requirements

1. **Inbound leg.** A correspondent writes to `you@example.com`. SES receives it, and the relay forwards it to `PRIVATE_ADDRESS` with From set to a generated reply address `reply+TOKEN@example.com`. The display name keeps the correspondent's identity. TOKEN maps back to the correspondent and to the alias that was written to.
2. **Outbound leg.** You reply in the private inbox. The reply goes to `reply+TOKEN@example.com`, SES receives it, and the relay rebuilds it with From `you@example.com` and To the correspondent, then sends it through SES.
3. **Kept intact:** subject, body (text and HTML), attachments, inline images, and threading on both sides.
4. **Stripped:** the private address everywhere in headers, the provider's routing headers (Received, X-Google-*, Return-Path, the original DKIM-Signature, Sender), and any Message-ID that names the provider.
5. **Only you can use the outbound leg.** A reply is relayed only when SES's authentication results prove it came from `PRIVATE_ADDRESS`, and the token is unguessable.
6. **No mail loops.** Auto-generated mail is never relayed outward, and the relay never relays its own output.
7. **New conversations** have a defined address convention (section 9).
8. **Stated limit:** the relay cannot catch the private address if you type it into a body or signature.
9. **Size and cost:** close to 40 MB per message each way, measured on the encoded message (about 28 MB of attachments, since base64 adds about a third), and pennies a month at personal volume.
10. **Minimal moving parts.**

### Non-goals

- Group threads. A reply goes only to the token's correspondent; other original recipients are listed in an informational header but cannot be replied to through the relay.
- A guaranteed body scrub of the private address.
- Mailbox storage. S3 keeps raw copies for 30 days for replay only.
- A web UI, multiple operators, or a second region.
- SMTPUTF8 (non-ASCII) addresses.

## 2. Architecture

```
                      INBOUND LEG
bob@example.org --SMTP--> SES (us-east-1) receipt rule "relay-inbound"
                              |  1. S3 action: raw/<sesMessageId>
                              |  2. Lambda action (Event): relay
                              v
                          relay Lambda --GetItem/PutItem--> DynamoDB "mailrelay"
                              |  reads raw object from S3
                              |  From: "Bob (bob at example.org)" <reply+TOKEN@example.com>
                              v
                          SES SendEmail (raw) --> private@example.net

                      OUTBOUND LEG
private@example.net --SMTP--> SES receipt rule "relay-inbound" (reply+TOKEN@example.com)
                              |  same S3 and Lambda actions
                              v
                          relay Lambda: authenticate, look up TOKEN
                              |  From: you@example.com  To: bob@example.org
                              v
                          SES SendEmail (raw) --> bob@example.org
```

Components, all in `us-east-1`:

| Component | Count | Purpose |
|---|---|---|
| SES receipt rule | 1 | Appended to the existing active rule set |
| S3 bucket | 1 | Raw messages; the Lambda event carries no body |
| Lambda function | 1 | Both legs, routed by recipient and authentication |
| DynamoDB table | 1 | Tokens, send claims, and threading anchors |
| IAM role | 1 | Least-privilege role for the function |
| Per-domain DNS and SES identity | 1 set per new domain | MX, DKIM, MAIL FROM, DMARC |

### Message flow, inbound

1. SES accepts mail for `you@example.com` because the rule's recipient condition matches it.
2. The S3 action writes the raw message to `raw/<sesMessageId>`.
3. The Lambda action invokes the function asynchronously with an SES event: headers, verdicts, and recipients, but no body.
4. The function checks verdicts, decides the leg (section 6), checks size, reads the raw object, mints or reuses the token, rewrites the headers, and sends the result to `PRIVATE_ADDRESS`.

### Message flow, outbound

1. You reply. Your provider sends the reply to `reply+TOKEN@example.com`.
2. SES stores and invokes as above. The event carries SES's SPF, DKIM, DMARC, spam, and virus verdicts.
3. The function authenticates the sender (section 8), resolves TOKEN to `{alias, peer}`, rebuilds the header block from an allowlist, and sends From the alias To the peer.
4. After a successful send, it stores the SES message id against your reply's Message-ID, so the correspondent's next reply threads under your sent message (section 7).

## 3. Design decisions

Each decision records the choice, the alternative rejected, and why.

**D1. One Lambda function for both legs.** Both legs share parsing, the header splice, token lookup, loop checks, and the send path. A second function would duplicate that code and add a second role, permission, and rule. It would let IAM pin the forward path's recipient, but this design already pins that path in IAM inside one role (D9), and the reply path must be able to send to arbitrary recipients in either design.

**D2. Tokens are random values stored in DynamoDB, not stateless signed tokens.** A stateless token must carry the correspondent address (up to 254 octets), the alias, and a MAC. RFC 5321 caps a local part at 64 octets ([RFC 5321, section 4.5.3.1.1](https://www.rfc-editor.org/rfc/rfc5321.html)), so a stateless token does not fit. A random token needs no secret key to manage or rotate. The same table also holds send claims (D10) and threading anchors (D3), so it serves three confirmed needs.

**D3. Threading by reversible wrapping of the correspondent's Message-IDs, plus one anchor item per reply.** SES overrides any Message-ID it is given ([SES header fields](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)). Wrapping keeps the correspondent's IDs recoverable without storing them, and makes it structurally impossible for a provider Message-ID to leave. A filter that keeps IDs by domain was rejected because it cannot tell a correspondent's provider IDs from your own provider's IDs when both use the same provider. Details in section 7.

**D4. Sender authentication reads SES's own Authentication-Results header as well as the event verdicts.** SES documents `dmarcVerdict` GRAY as covering domains with no DMARC policy or `p=none` where at least one of SPF or DKIM passed, and that wording does not prove the pass was aligned with the From domain ([SES receipt notification contents](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html)). The same page defines `dkimVerdict` GRAY as "not DKIM-signed or the from domain and DKIM-signature domain do not match", which suggests PASS already implies alignment, but the page does not say so outright. So the relay also requires an aligned `dkim=pass` entry in the header SES adds to the stored copy ([SES email receiving concepts](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html)). Details in section 8.

**D5. New conversations use `<alias>+<local>=<domain>@<relay domain>`.** It names the sending alias, needs no new subdomain, MX, or rule, and reuses the same authentication. The floated alternative, `someone_at_example.com@relay.example.com`, needs a receiving subdomain with its own MX and identity, and `_at_` is ambiguous when a real local part contains it. Details in section 9.

**D6. Reuse the active rule set and append one rule.** Only one receipt rule set can be active ([SES receipt rules walkthrough](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html)). Creating and activating a second set would switch off the two existing rules. Details in section 10.

**D7. Python 3.12, inline in CloudFormation.** The account's existing support forwarder is a single CloudFormation template with an inline Python 3.12 Lambda, and its header-splice and address-validation code carries over. The standard `email` package handles headers and `boto3` ships in the Python runtime ([Lambda Python runtime](https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html)), so there are no dependencies to package. Inline `ZipFile` code may be up to 4 MB ([CloudFormation Lambda Code](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-code.html)). Node was rejected because it would need a MIME library or hand parsing and would diverge from the precedent.

**D8. S3 storage is required.** The Lambda action's event does not contain the message body ([SES Lambda action](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-lambda.html)). The SNS action carries at most 150 KB ([SES quotas](https://docs.aws.amazon.com/ses/latest/dg/quotas.html)). The S3 action stores messages up to 40 MB ([SES S3 action](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-s3.html)). The bucket is a short replay buffer: versioning off and a 30-day expiry, because stored replies contain the private address.

**D9. One IAM role with two scoped SES send statements.** Section 12.

**D10. One idempotency claim per send.** Lambda retries a failed asynchronous invocation twice by default and can deliver the same event more than once ([Lambda asynchronous error handling](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html)). A conditional put before each send, deleted if the send raises a transient error, blocks duplicate sends from duplicate events and lets a transient failure retry. It has stated limits (a hard kill mid-send, a lost send response, exhausted retries); in each case the raw copy stays in S3 for replay. Details in section 14.

**D11. A dry-run switch for the reply leg.** With `OutboundEnabled=false`, the function runs every outbound check and logs the decision but sends nothing. The spoof test (section 16) runs in this mode before the reply leg goes live.

## 4. Token scheme and data model

### Token

- 16 bytes from `secrets.token_bytes(16)` (128 bits), base32 encoded, lowercased, padding removed: 26 characters from `[a-z2-7]`.
- Reply address: `reply+<token>@<relay domain>`, a 32-octet local part.
- Lowercase because the relay lowercases recipients before lookup, and some mail systems fold case (**Unverified** for any specific system; harmless either way, so nothing needs settling).
- Stable per (alias, correspondent): the same correspondent writing to the same alias always gets the same reply address, so the private inbox's contact list holds one entry per correspondent.

The token is defense in depth, not the security boundary. It appears in the quoted attribution of your replies ("On ... <reply+TOKEN@example.com> wrote:"), so correspondents can learn it. Sender authentication (section 8) is what stops anyone else from sending as you.

### Who the token points to

The peer is the correspondent's single valid `Reply-To` address when present, otherwise the single valid `From` address, otherwise the envelope sender. This matters for contact forms and ticket systems that send From `no-reply@` with Reply-To set to the real person.

### Table `mailrelay`

On-demand capacity, partition key `pk` (string) only, TTL attribute `expires`, `DeletionPolicy: Retain`. TTL deletes consume no write capacity ([DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html)).

| `pk` | Attributes | TTL | Written when |
|---|---|---|---|
| `t#<token>` | `alias`, `peer`, `name` (display name) | none | First contact for a pair |
| `p#<alias>#<peer>` | `token` | none | First contact for a pair, conditional put |
| `d#<key>#<recipient>` | `created` | 30 days | Before each send (D10) |
| `o#<SES MessageId>` | `mid` (your reply's own Message-ID) | 400 days | After each outbound send (section 7) |

Minting, race-safe:

```python
def get_or_mint_token(alias, peer, name):
    pair = f"p#{alias}#{peer}"
    item = table.get_item(Key={"pk": pair}).get("Item")
    if item:
        return item["token"]
    token = base64.b32encode(secrets.token_bytes(16)).decode().rstrip("=").lower()
    table.put_item(Item={"pk": f"t#{token}", "alias": alias, "peer": peer, "name": name})
    try:
        table.put_item(Item={"pk": pair, "token": token},
                       ConditionExpression="attribute_not_exists(pk)")
        return token
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        # A concurrent first contact won; reuse its token. The orphan t# item is harmless.
        return table.get_item(Key={"pk": pair}, ConsistentRead=True)["Item"]["token"]
```

Tokens never expire, so old reply addresses keep working.

## 5. Header and MIME handling

### MIME

Both legs rewrite only the top-level header block. The body bytes after the first blank line pass through unchanged, so text and HTML alternatives, attachments, inline images referenced by `cid:`, nested parts, and boundaries all survive byte for byte. The existing support forwarder uses the same splice (split at the first `\r\n\r\n` or `\n\n`, group continuation lines with their header, filter groups, prepend new headers).

New headers with non-ASCII display names or subjects are RFC 2047 encoded (`email.headerregistry` or `email.utils.formataddr` with a `Header`), because SES requires 7-bit headers ([SES raw sending](https://docs.aws.amazon.com/ses/latest/dg/send-email-raw.html)). Lines stay under 1,000 characters ([SESv2 RawMessage](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_RawMessage.html)); long References values are folded.

SES rejects a header field that appears more than once when the field may occur only once (for example Subject, References, In-Reply-To, Auto-Submitted, List-Id) ([SES header fields](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)). Before sending, the relay keeps only the first occurrence of each such field.

### Inbound leg (correspondent to private inbox): denylist plus rewrites

| Header | Action |
|---|---|
| From | Rewrite to `"<display name> (<local> at <domain>)" <reply+TOKEN@example.com>`; see section 23 item 15 for why the name never holds an `@` |
| To | Rewrite to `PRIVATE_ADDRESS` (so reply-all treats it as "self" and leaves it out) |
| Reply-To | Rewrite to `reply+TOKEN@example.com` |
| Cc, Bcc | Strip, so reply-all cannot mail third parties directly from the private inbox. Original To and Cc are copied to `X-Relay-Original-To` and `X-Relay-Original-Cc` for information |
| Sender, Return-Path, Delivered-To | Strip |
| DKIM-Signature, DomainKey-Signature, ARC-*, Authentication-Results, Received-SPF | Strip (signatures no longer verify; SES signs the new message) |
| X-SES-*, Resent-*, Content-Length, X-Relay-* (incoming) | Strip |
| Auto-Submitted | Strip, then add `Auto-Submitted: auto-forwarded` |
| Message-ID | Strip; SES assigns a new one. The value is appended (wrapped) to References |
| In-Reply-To, References | Wrap or anchor each ID (section 7) |
| List-Unsubscribe, List-Unsubscribe-Post | Strip: a mailto unsubscribe would mail the list from the private address |
| Disposition-Notification-To, Return-Receipt-To | Strip: a read receipt would go out directly from the private inbox |
| Subject, Date, MIME-Version, Content-*, List-Id, Received, other headers | Keep (SES overrides Date) |
| Added | `X-Relay-Hop: v1` (loop marker); `X-Relay-Spam: gray` when the spam verdict is GRAY |

### Outbound leg (private inbox to correspondent): allowlist

An allowlist, because providers add headers that cannot be listed in advance (X-Google-*, X-Gm-*, X-Apple-*, User-Agent, X-Mailer, and others).

| Header | Action |
|---|---|
| Subject, MIME-Version | Keep |
| Every `Content-*` except Content-Length | Keep (single-part replies need Content-Disposition and Content-ID) |
| From | Set to `"<AliasDisplayName>" <alias>` |
| To | Set to the peer from the token, or the compose target |
| In-Reply-To, References | Rebuild by unwrapping (section 7) |
| Added | `X-Relay-Hop: v1` |
| Everything else | Drop, including Received, Return-Path, Sender, Reply-To, Cc, Bcc, DKIM-Signature, ARC-*, Authentication-Results, X-Google-*, X-Gm-*, User-Agent, X-Mailer, Thread-Index, Message-ID, Date |

Final guard: if the rebuilt header block contains `PRIVATE_ADDRESS` (case-insensitive), the relay refuses to send and notifies you. The guard matches the exact address, not the private domain, because a correspondent who uses the same provider would trip a domain match.

## 6. Leg routing, loop and abuse defenses

For each record, and for each recipient in `receipt.recipients` (the envelope recipients the rule matched, per the [receipt notification contents](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html)) that is on a relay domain:

1. If the message carries `X-Relay-Hop`, drop (own output).
2. If the local part is `reply+<token>`: the **reply** path. Run sender authentication; on failure drop silently.
3. If the local part is `<alias>+<label>` where `<alias>` is a configured alias and `<label>` contains `=`, and sender authentication passes: the **compose** path (section 9).
4. If the local part is an alias, with or without a `+label`: the **inbound** path.
5. Otherwise drop with a log line.

`relay@<domain>`, the From address of notices, is not a rule recipient, so SES rejects any mail sent to it (including bounces of notices) before the relay sees it.

The support forwarder handles only the first accepted recipient. The relay loops over all matched recipients, each with its own claim and send.

### Loop and abuse defenses

Both legs:

- Any message carrying `X-Relay-Hop` is dropped: it is the relay's own output coming back.
- Reserved concurrency 2 bounds runaway cost, and the account's sending quota (14 per second) bounds volume.

Inbound leg:

- Verdicts: virus not PASS, spam FAIL, or DMARC FAIL with `dmarcPolicy` `reject` or `quarantine` means quarantine: the raw copy stays in S3, nothing is forwarded, and a log line is written. Spam GRAY is forwarded with `X-Relay-Spam: gray`. (The support forwarder quarantines anything not PASS; a personal inbox cannot afford to lose GRAY mail.)
- Mail whose From, Reply-To, or envelope sender is a relay-domain address or `PRIVATE_ADDRESS` is dropped: it is either the relay's output with the marker stripped or you writing to your own alias. No token is ever minted for those addresses. The build narrows this rule: see section 23, items 3 and 13.
- Auto-generated mail (vacation replies, bounces, receipts) and list mail are forwarded, because you want them. They cannot loop: the forward carries `Auto-Submitted: auto-forwarded`, which vacation responders are expected to honor, since RFC 3834 says not to auto-reply to mail whose Auto-Submitted is anything other than `no` (**Unverified** per responder; live test L4 settles it for yours), and any reply to them must pass the outbound checks below.

Outbound leg (reply and compose), after authentication:

- Refused with a notice: `Auto-Submitted` present with any value other than `no`; `Precedence` of `bulk`, `junk`, `list`, or `auto_reply`; a `List-Id` header; `Content-Type: multipart/report`; a peer or compose target on a relay domain or equal to `PRIVATE_ADDRESS`.
- These stop a vacation responder or delivery report in the private inbox from answering through the relay.

## 7. Threading across rewritten Message-IDs

SES replaces the Message-ID of every message it sends ([SES header fields](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)). Neither side ever sees the other side's real Message-IDs, so the relay translates References and In-Reply-To (constructed per [RFC 5322 section 3.6.4](https://www.rfc-editor.org/rfc/rfc5322)).

### Wrapping (inbound) and unwrapping (outbound)

```python
REF_DOMAIN = "ref." + relay_domain            # e.g. ref.example.com

def wrap(msg_id):                              # msg_id without angle brackets
    enc = base64.b32encode(msg_id.encode()).decode().rstrip("=").lower()
    return f"<x.{enc}@{REF_DOMAIN}>"

def unwrap(token):                             # returns None for anything not ours
    local, _, domain = token.strip("<>").rpartition("@")
    if domain != REF_DOMAIN or not local.startswith("x."):
        return None
    enc = local[2:].upper()
    try:
        value = base64.b32decode(enc + "=" * (-len(enc) % 8)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None                            # malformed: drop the ID, never raise
    if not value or any(not 32 < ord(c) < 127 or c in "<>" for c in value):
        return None
    return "<" + value + ">"
```

**Inbound.** For each ID in In-Reply-To and References (last 20), and for the correspondent's own Message-ID appended to the end of References:

- If the ID's part before `@` equals a stored `o#<SES MessageId>`, replace it with the stored `mid`: your own sent reply's Message-ID. Your client then sees its own sent message as the parent and threads.
- Otherwise wrap it.

**Outbound.** For each ID in In-Reply-To and References: unwrap it if it is under `@ref.<relay domain>`; drop it otherwise. That drops SES IDs of forwards and every provider Message-ID, including your own client's. In-Reply-To becomes the last unwrapped ID. After the send succeeds, write `o#<SES MessageId of this send>` = your reply's Message-ID.

### Trace

1. Bob sends `c1`. The forward gets SES ID `s1`. You see References `w(c1)`.
2. You reply `p1` (References `w(c1) s1`, In-Reply-To `s1`). Outbound unwraps `w(c1)`, drops `s1`: Bob receives In-Reply-To `c1`, References `c1`. The send gets SES ID `s2`; store `o#s2 = p1`.
3. Bob replies `c2` (References `c1 s2`). Inbound: `c1` becomes `w(c1)`, `s2` anchors to `p1`, `c2` is wrapped and appended: References `w(c1) p1 w(c2)`, In-Reply-To `p1`. Your client finds `p1`, its own sent message, and threads.
4. You reply `p2` (References `w(c1) p1 w(c2) s3`). Outbound keeps `c1` and `c2` and drops `p1` and `s3`. Bob's client knows both and threads.

No provider Message-ID crosses to Bob in any step, because outbound passes only IDs that inbound wrapped, and inbound wrapped only IDs that came from Bob's side.

**Unverified:** the anchor assumes the Message-ID header SES puts on the wire has the API's `MessageId` as its part before `@` (commonly seen as `<MessageId@email.amazonses.com>`). If it does not, only the anchor fails: your client falls back to grouping by References and subject, and nothing leaks. Settled by live test L3. Gmail documents that References must name IDs of earlier messages to thread ([Gmail threading changes](https://workspaceupdates.googleblog.com/2019/03/threading-changes-in-gmail-conversation-view.html)), which is why the anchor exists.

A composed message (section 9) has no prior IDs; the thread starts on your side when the correspondent first replies, anchored by `o#`.

## 8. Sender authentication for the outbound leg

The reply and compose paths relay a message only when **every** condition holds. A failure of conditions 1 to 6 (the sender is not proven to be you) drops the message, keeps the raw copy in S3, and writes a log line; no bounce or notice goes to the sender, so there is no backscatter and no oracle for valid tokens. A failure after authentication (condition 7, or the outbound checks in section 6 and 14) sends you a notice. Condition 8 failing means the message was already sent or is in flight, and the relay returns quietly. With `OutboundEnabled=false`, conditions 1 to 7 are evaluated, the claim (condition 8) is not taken, the decision is logged, and nothing is sent.

1. `receipt.virusVerdict.status == "PASS"` and `receipt.spamVerdict.status != "FAIL"`.
2. `receipt.dkimVerdict.status == "PASS"` and `receipt.dmarcVerdict.status != "FAIL"`. DMARC GRAY is accepted because SES reports GRAY for domains with no policy or `p=none` ([receipt notification contents](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html)).
3. **Aligned DKIM from SES's own header.** The topmost `Authentication-Results` header in the stored raw message is the one SES added (**Unverified** as documented behavior; settled by the same stored-message inspection below); senders can insert their own lower down, so only the topmost is read. It must contain a `dkim=pass` entry whose `header.i` (with or without a leading `@`) or `header.d` domain equals the private address's domain or is a subdomain of it. A missing or unparseable header fails closed. AWS documents that SES adds this header to the stored copy, and its example shows one `dkim=` entry per signature with a placeholder authserv-id and `header.i` without `@` ([SES email receiving concepts](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html)). Messages stored by SES in this account show the authserv-id `amazonses.com` and the form `dkim=pass header.i=@<domain>`. **Unverified as documented behavior:** before coding the parser (step 10), confirm the exact form, with the operator's leave, from one stored message in an existing SES inbound bucket in this account, or from a test message sent to a throwaway receipt rule.
4. The raw `From` header holds exactly one address, equal to `PRIVATE_ADDRESS` (domain compared case-insensitively). A `Sender` header, if present, holds the same address. There is no fallback to the envelope sender.
5. The envelope sender (`mail.source`) is not empty.
6. The envelope recipient also appears in the raw `To` or `Cc` header. Providers usually sign `To` (**Unverified**), so a captured signed message cannot be re-sent to a different reply address.
7. For the reply path, the token exists and its alias is on the recipient's domain.
8. The send claim succeeds (section 14). Its key on these paths is your Message-ID plus the recipient, which also blocks replay of a captured signed message for the 30-day life of the claim (condition 6 and the signed To header limit replay after that).

SPF is logged, not required: it covers the envelope domain, which an attacker chooses, and aligned DKIM already proves the domain.

**Residual trust.** The relay trusts the private inbox's provider not to let another account sign mail with `From: private@example.net`. Large providers enforce this (**Unverified**). On a shared custom domain, any user with access to that domain's DKIM-signed outbound mail could forge the local part; the private inbox should be on a domain only you control or on a large provider.

## 9. New-conversation convention

To start a thread with `bob@example.org` from the alias `you@example.com`, address your message to:

```
you+bob=example.org@example.com
```

Rules:

- Recognized only when the label after `+` contains `=` and sender authentication conditions 1 to 6 pass; the send then takes the claim (condition 8) like a reply. The same address from anyone else is ordinary inbound mail to `you@example.com`, which is how ordinary plus-addressing keeps working.
- The label is split on its **last** `=`; a domain cannot contain `=`, and `=` is legal in a local part. `bob+news=example.org` yields `bob+news@example.org`.
- The target is validated with the same address check the inbound leg uses, and must not be on a relay domain or equal `PRIVATE_ADDRESS`.
- The message is sent From `you@example.com` To the target, and the pair token is minted or reused, so the correspondent's reply returns through the inbound leg.
- Limit: the whole local part, `you+bob=example.org`, must fit in 64 octets. A longer target gets a notice; the correspondent has to write first.

The receipt rule needs no change: an address condition also matches its `+label` forms ([SES receipt rules walkthrough](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html)).

## 10. SES receipt rule design

The account has one active rule set, `default-rule-set`, with two rules in this order:

1. `other-inbound`: recipient `other.example` (whole domain), scan on; actions S3 then Lambda (Event); **no Stop**.
2. `helpdesk-inbound`: recipients `support@shared.example` and `security@shared.example`, scan on; actions S3, Lambda (Event), then Stop (scope RuleSet).

Only one rule set can be active ([SES receipt rules walkthrough](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html)). Never create or activate another set, and never call `SetActiveReceiptRuleSet`: activating a different set turns off both existing rules.

New rule, appended last:

| Property | Value |
|---|---|
| Rule set | `default-rule-set` |
| Name | `relay-inbound` |
| After | `helpdesk-inbound` |
| Enabled | `RuleEnabled` parameter |
| Recipients | Each alias address, plus `reply@<domain>` for each relay domain. Address conditions also match `+label` forms, so `reply+TOKEN@` and `you+bob=example.org@` match. SES rejects mail to recipients no rule matches ([SES email receiving concepts](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html)), so there is no catch-all |
| ScanEnabled | true |
| TlsPolicy | Optional |
| Actions | S3 (`raw/`), Lambda (Event), Stop (scope RuleSet) |

Appending last cannot change how the two existing rules run. Changing `After` updates the rule without interruption ([CloudFormation ReceiptRule](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-receiptrule.html)), while renaming a rule replaces it ([CloudFormation ReceiptRule Rule property](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ses-receiptrule-rule.html)). A rule set holds up to 200 rules ([SES quotas](https://docs.aws.amazon.com/ses/latest/dg/quotas.html)). The quotas page lists 500 recipients per rule while the walkthrough page says 100 recipient conditions per rule; plan for at most 100 recipient conditions per rule (aliases plus one `reply@` per domain).

### Choosing relay domains

| Domain kind | Use? | Notes |
|---|---|---|
| A Route 53 zone with no MX record | Recommended | Deploy `relay-domain.yml` for it. No other rule matches addresses there. One message addressed both to an alias and to a recipient of an earlier rule can still be affected by that rule (see the next rows and L10) |
| `other.example` | No | Its whole-domain rule has no Stop, so both rules would act on the same message |
| `shared.example` | Possible, with limits | Aliases must not be `support@` or `security@` (or their `+label` forms). Deploy `relay.yml` only, because the support stack already owns this domain's MX, MAIL FROM, and DMARC records, and the domain's SES identity already exists outside that stack. A single message addressed to both a support address and an alias (on any relay domain) probably stops at `helpdesk-inbound`'s Stop before reaching the relay, because SES runs a rule's actions on the whole message when any recipient matches ([SES ReceiptRule API](https://docs.aws.amazon.com/ses/latest/APIReference/API_ReceiptRule.html)); **Unverified**, settled by live test L10 |
| The apex of a domain whose MX points at Google Workspace | No | Moving its MX to SES would take all of its mail. A subdomain (for example `r.<domain>`) with its own MX and identity works |

## 11. DNS records per relay domain

For a new relay domain (none of these exist yet), `relay-domain.yml` creates, in its Route 53 hosted zone:

| Record | Type | Value | Source |
|---|---|---|---|
| `example.com.` | MX | `10 inbound-smtp.us-east-1.amazonaws.com.` | [SES MX record](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-mx-record.html) |
| Three DKIM names from the identity | CNAME | From `DkimDNSTokenName1..3` and `DkimDNSTokenValue1..3` | [CloudFormation EmailIdentity](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-emailidentity.html) |
| `mail.example.com.` | MX | `10 feedback-smtp.us-east-1.amazonses.com.` | Custom MAIL FROM ([SES MAIL FROM domain](https://docs.aws.amazon.com/ses/latest/dg/mail-from.html)), same as the support stack |
| `mail.example.com.` | TXT | `"v=spf1 include:amazonses.com ~all"` | Custom MAIL FROM, same as the support stack |
| `_dmarc.example.com.` | TXT | `"v=DMARC1; p=none"`, raised to `p=quarantine` after a clean week | |

Plus `AWS::SES::EmailIdentity` for the domain with Easy DKIM and `MailFromAttributes` set to `mail.example.com`.

The MX record is created last and sits behind an `EnableMx` condition, because the MX is the switch that makes mail flow. For a domain that already has an SES identity and DNS (for example `shared.example`), skip `relay-domain.yml` entirely.

## 12. IAM permissions

One role, `mailrelay`, trusted by `lambda.amazonaws.com`:

| Sid | Actions | Resource | Condition |
|---|---|---|---|
| Logs | `logs:CreateLogStream`, `logs:PutLogEvents` | The function's log group | |
| ReadRaw | `s3:GetObject` | `arn:aws:s3:::<bucket>/raw/*` | |
| Table | `dynamodb:GetItem`, `PutItem`, `DeleteItem` | The table ARN | |
| SendForward | `ses:SendRawEmail` | `arn:aws:ses:us-east-1:123456789012:identity/<domain>` per relay domain | `StringLike ses:FromAddress` in `reply+*@<domain>`, `relay@<domain>`; `ForAllValues:StringEquals ses:Recipients` = `PRIVATE_ADDRESS` |
| SendReply | `ses:SendRawEmail` | Same identity ARNs | `StringEquals ses:FromAddress` in the alias list; no recipient condition |

The `ses:FromAddress` and `ses:Recipients` conditions are documented in [Controlling access to SES](https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html). Forwards and notices can therefore only ever go to the private inbox; only an alias can send to arbitrary recipients.

**Unverified:** that `ses:SendRawEmail` alone authorizes an SESv2 `SendEmail` call with raw content. The existing support forwarder grants only that action and sends with SESv2 raw content, which suggests it does. Settled by the first inbound forward in rollout step 5 (and by L2 for the reply statement); if it is refused, add `ses:SendEmail` to both send statements with the same conditions.

Resource policies ([SES receiving permissions](https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html)), both pinned to the rule's ARN `arn:aws:ses:us-east-1:123456789012:receipt-rule-set/default-rule-set:receipt-rule/relay-inbound` with `AWS:SourceAccount`:

- Bucket policy: allow `ses.amazonaws.com` `s3:PutObject` on `raw/*`.
- Lambda permission: allow `ses.amazonaws.com` `lambda:InvokeFunction`.

## 13. Configuration parameters

`relay.yml` parameters, passed to the function as environment variables where relevant:

| Parameter | Example or default | Purpose |
|---|---|---|
| `Domains` | `example.com` | Relay domains (comma list) |
| `Aliases` | `you@example.com` | Alias addresses (comma list); `scripts/render.py` expands them into rule recipients and IAM conditions |
| `AliasDisplayName` | `You` | Display name on outbound From |
| `PrivateAddress` | `private@example.net` | The private inbox |
| `MaxBytes` | `39845888` (38 MiB) | Size cap; leaves room for added headers under the 40 MB send limit |
| `RetentionDays` | `30` | Expiry for `raw/` |
| `RuleEnabled` | `true` | Enables the receipt rule |
| `OutboundEnabled` | `false` | Dry-run switch for the reply and compose paths (D11) |
| `ScrubBody` | `false` | Optional body scrub (section 19) |

`relay-domain.yml` parameters: `Domain`, `HostedZoneId`, `EnableMx` (default `false`).

Function settings: Python 3.12, 1024 MB, 120 s timeout, reserved concurrency 2. The memory figure is an estimate for holding a 38 MiB message plus its encoded request; live test L6 confirms it.

## 14. Failure handling, bounces, and observability

### Raise or return

- **Raise** (Lambda retries twice): S3 read errors, DynamoDB errors before the send, and SES send errors that are transient (throttling, 5xx).
- **Return** (no retry): drops, quarantine, loops, oversize, authentication failure, and permanent SES rejects.
- After a successful send, the `o#` anchor write is best effort and logged, never raised, so a send is never repeated.

### Send claims

Before each send, a conditional put of `d#<key>#<recipient>` with `attribute_not_exists(pk)`. The key is the SES `mail.messageId` on the inbound leg and your reply's Message-ID on the reply and compose paths. If the put fails, the message was already sent or is in flight: return. If the send raises a transient error, delete the claim and re-raise so the retry can run; on a permanent reject keep the claim, send the notice, and return. A crash after a successful send cannot cause a duplicate, because the claim stays.

Limits, stated rather than solved: a hard kill (timeout, out of memory) between the claim and the send's return leaves the claim, so Lambda's retry finds the claim and returns without sending; a send whose response is lost after SES accepted it raises, and the retry sends it a second time; after three failed attempts (about three minutes) Lambda discards the event, and this design has no failure destination. SES can also accept a message and then not deliver it, for example when it finds a virus ([SESv2 SendEmail](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html)). Events throttled by the reserved concurrency of 2 are retried by Lambda for up to 6 hours and then discarded. In every case the raw copy stays in S3 and can be replayed (see Replay); a hard kill or a discarded event may leave no log line naming it.

### Notices to you

Oversize or otherwise failing mail to a reply or compose address from anyone other than you is dropped silently, like any authentication failure. Notices are sent From `relay@<domain>` to `PRIVATE_ADDRESS` only, carrying `X-Relay-Hop: v1` and `Auto-Submitted: auto-generated`, with the original sender, subject, and S3 key, never the body:

- Every inbound permanent reject on the inbound path: oversize, or SES refusing the forward (it rejects 90 attachment file extensions such as `.exe`, `.js`, and `.msi` ([SES attachments](https://docs.aws.amazon.com/ses/latest/dg/attachments.html)), and lines over 1,000 characters ([SESv2 RawMessage](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_RawMessage.html))).
- Every authenticated outbound failure: unknown token, invalid compose target, auto-generated reply, oversize, header guard, or SES rejection.

### Bounces

SES forwards bounce and complaint feedback by email by default, to the Return-Path header address if the raw message has one, otherwise the sender given in the API call, otherwise the From header ([SES email feedback notifications](https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity-using-notifications-email.html)). The relay strips Return-Path and sets the API sender equal to From, so feedback goes to the From address. That order is documented for `SendRawEmail`; applying it to the SESv2 call is an inference that live test L5 checks.

- A relayed reply that bounces returns feedback to `you@example.com`; it arrives as ordinary inbound mail and is forwarded to you.
- A forward that the private provider bounces returns feedback to `reply+TOKEN@example.com` from a mailer daemon; it fails authentication and is dropped with a log line. Persistent forward bounces show only in the logs (section 19).
- Sends to addresses on the account-level suppression list are accepted by SES but not sent, when the address's suppression reason matches the account's suppression setting ([SES suppression list](https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html)).

### Observability

- One JSON log line per recipient: `leg`, `outcome` (`forwarded`, `relayed`, `composed`, `dropped:<reason>`, `quarantined`, `notice`, `error`), inbound and outbound SES IDs, the first 6 characters of the token, and the verdicts. No addresses, subjects, or bodies.
- Log retention 30 days.
- Lambda `Errors` and `Throttles` metrics. An alarm is optional and not in the core stack, because it needs an SNS topic.

### Replay

Raw messages stay in `raw/` for 30 days. To replay one, invoke the function with a synthetic SES event naming its `messageId` (`aws lambda invoke` with a JSON payload). Claims make a replay of an already-sent message a no-op; delete the `d#` item first to force a resend.

## 15. Limits and cost

### Limits

All from [SES quotas](https://docs.aws.amazon.com/ses/latest/dg/quotas.html) unless noted:

| Limit | Value |
|---|---|
| Receiving, stored to S3 | 40 MB per message, headers included |
| Sending, SESv2 API or SMTP | 40 MB per message after encoding (the v1 API allows 10 MB, which is why SESv2 is used) |
| MIME parts per sent message | 500 |
| Recipients per sent message | 50 |
| Lambda event headers | 50 KB |
| Relay cap | 38 MiB (`MaxBytes`); larger mail is archived and you get a notice |
| Account sending quota | 50,000 per 24 hours, 14 per second (this account, production access) |

The forwarded message is the original, already-encoded MIME plus a few hundred bytes of headers, so a message accepted at 38 MiB should fit the 40 MB send limit (**Unverified**: whether MB is decimal and what "after base64 encoding" covers; live test L6 settles it). The private inbox's provider may have a lower limit of its own for what you can send.

### Cost model

Prices in `us-east-1` from [SES pricing](https://aws.amazon.com/ses/pricing/), [Lambda pricing](https://aws.amazon.com/lambda/pricing/), and [DynamoDB on-demand pricing](https://aws.amazon.com/dynamodb/pricing/on-demand/):

| Item | Rate |
|---|---|
| SES receiving | $0.10 per 1,000 messages, plus $0.09 per 1,000 incoming 256 KB chunks |
| SES sending | $0.10 per 1,000 messages, plus $0.12 per GB of attachments |
| Lambda | $0.20 per million requests and $0.0000166667 per GB-second, after a monthly free tier of 1 million requests and 400,000 GB-seconds |
| DynamoDB on-demand | $0.625 per million writes, $0.125 per million reads |
| S3 storage | about $0.023 per GB-month (**Unverified**, from memory; settled by [S3 pricing](https://aws.amazon.com/s3/pricing/)) |

Worked example: 1,000 inbound messages and 300 replies a month, 100 KB average.

| Item | Cost |
|---|---|
| SES receiving: 1,300 messages and at most 1,300 chunks (**Unverified**: how messages under 256 KB are counted; the first bill settles it) | $0.13 + up to $0.12 |
| SES sending: 1,300 messages | $0.13 |
| SES attachment data: about 0.13 GB | $0.02 |
| Lambda: 1,300 invocations at about 2 GB-seconds each | $0 (free tier) |
| DynamoDB: about 3,000 writes and up to about 25,000 reads (one per threading ID) | under $0.01 |
| S3: about 0.13 GB held for 30 days | under $0.01 |
| **Total** | **about $0.29 to $0.41 a month** |

Cost scales linearly with message count and size. **Unverified:** which SES pricing plan this account is on. The pricing page describes plans in which outbound costs $0.16 per 1,000; on such a plan the example rises by about $0.08.

## 16. Test plan

### Unit tests

`pytest`, with the function's source loaded from `src/relay.py`, `boto3` clients stubbed, and `.eml` fixtures in `tests/fixtures/`.

| ID | Case | Expected |
|---|---|---|
| U1 | Inbound plain text | From is `"Bob (bob at example.org)" <reply+[a-z2-7]{26}@example.com>`, To is `PRIVATE_ADDRESS`, body bytes identical (hash compare), `t#` and `p#` items written |
| U2 | Inbound multipart/alternative, multipart/related with an inline `cid:` image, multipart/mixed with a PDF | Body bytes identical |
| U3 | Inbound with Reply-To different from From | Token peer is the Reply-To address |
| U4 | Inbound with Cc, Bcc, List-Unsubscribe, Disposition-Notification-To | Each stripped; `X-Relay-Original-Cc` present |
| U5 | Inbound auto-reply carrying Auto-Submitted, and a duplicate Subject | One `Auto-Submitted: auto-forwarded`; one Subject |
| U6 | Same correspondent twice; same correspondent to two aliases | One token; two tokens |
| U7 | Gmail-style outbound reply with X-Gm-*, X-Google-*, Received, a provider Message-ID | Only allowlisted headers remain; `PRIVATE_ADDRESS` and the provider Message-ID appear nowhere in the header block |
| U8 | Threading trace from section 7, steps 1 to 4 | Exact In-Reply-To and References on each side |
| U9 | Auth matrix: DKIM FAIL; DKIM GRAY; `dkim=pass` only for a different domain in the topmost Authentication-Results; a forged `amazonses.com` Authentication-Results below the real one; missing Authentication-Results; DMARC FAIL; From not private; two From addresses; Sender mismatch; empty envelope sender; envelope recipient not in To or Cc | Each dropped, nothing sent |
| U10 | Aligned `dkim=pass` with DMARC GRAY | Relayed |
| U11 | Unknown token from the authenticated sender; from a stranger | Notice; silent drop |
| U12 | Compose: `you+bob=example.org@`; `you+a+b=example.org@`; no `=`; target on a relay domain; 70-octet local part; from a stranger | Sent; sent to `a+b@example.org`; dropped (From is `PRIVATE_ADDRESS`); refused with notice; notice; forwarded inbound |
| U13 | Loops: `X-Relay-Hop` on each leg; outbound `Auto-Submitted: auto-replied`; `Precedence: bulk`; `multipart/report`; inbound From an alias or `PRIVATE_ADDRESS` | Own output (`X-Relay-Hop`) dropped on both legs; the auto-generated, bulk, and report cases refused on the outbound leg only (inbound forwards them); inbound From an alias or `PRIVATE_ADDRESS` dropped |
| U14 | Same event twice; send raises once then succeeds | One send; claim released then re-taken |
| U15 | Oversize object (stubbed length) | Notice, no forward |
| U16 | Non-ASCII display name and subject | RFC 2047 encoded headers |
| U17 | `OutboundEnabled=false` with a valid reply | Decision logged as relay, nothing sent |
| U18 | Header guard: private address injected into a kept header | Refused with notice |

### Live tests

Run on a relay domain with no other mail, from the real private inbox and a test correspondent account at a different provider.

| ID | Case | Pass condition |
|---|---|---|
| L0 | Reply from the private inbox with `OutboundEnabled=false` | Log shows conditions 1 to 7 passing (the claim is not taken in dry run); record the raw Authentication-Results form |
| L1 | **Spoof test, gate.** From a server you control with valid SPF and DKIM for its own domain, send to a real `reply+TOKEN` address with `From: private@example.net` | Dropped. Repeat with a message sent from a different account at the private inbox's provider. Only after both pass, set `OutboundEnabled=true` |
| L2 | Round trip with an HTML body, an inline image, and a 5 MB PDF | Renders intact on both sides; the correspondent's raw source contains neither `PRIVATE_ADDRESS` nor the provider's name in any header |
| L3 | Four-message thread | One thread in Gmail and Apple Mail on both sides; record the SES Message-ID header form (settles the section 7 anchor) |
| L4 | Gmail vacation responder turned on in the private inbox | No outbound mail results |
| L5 | Reply to a nonexistent correspondent address | Exactly one bounce forwarded to you through the inbound leg |
| L6 | 27 MB attachment each way (about 37 MB encoded), or outbound the largest the private provider allows; a 38.1 MiB message inbound | Delivered; the oversize message produces a notice. Record Lambda peak memory |
| L7 | Compose to a new address | Delivered From the alias; the correspondent's reply returns through the inbound leg |
| L8 | Mail to `support@shared.example` and to any `other.example` address | Still reaches their existing forwarders unchanged |
| L9 | Read-only `DescribeActiveReceiptRuleSet` | Order `other-inbound`, `helpdesk-inbound`, `relay-inbound`; the first two unchanged |
| L10 | One message to `support@shared.example` and an alias; one message to a `other.example` address and an alias | Records whether the alias copy reaches the relay after `helpdesk-inbound`'s Stop, and that both rules act in the second case |

## 17. Repository layout and file inventory

```
serverless-mail/
  PLAN.md                  this document
  README.md                parameters, deploy order, compose convention, limits, replay, rollback
  relay.yml                core stack: bucket, policy, table, log group, role, function, permission, rule
  relay-domain.yml         per new domain: SES identity, DKIM, MAIL FROM, DMARC, MX
  src/relay.py             the function; spliced into relay.yml at deploy time
  scripts/render.py        writes src/relay.py into the ZipFile block of a rendered template
  scripts/deploy.sh        render, deploy domain stacks, deploy core stack, print rule order
  tests/test_relay.py      unit tests U1 to U18
  tests/fixtures/*.eml     message fixtures
```

## 18. Rollout and rollback

### Rollout

1. Run the precondition check in section 0.
2. For each new relay domain, deploy `relay-domain.yml` with `EnableMx=false`. Wait until the identity's DKIM status is verified.
3. Take a read-only snapshot of the active rule set (`DescribeActiveReceiptRuleSet`).
4. Deploy `relay.yml` with `RuleEnabled=false` and `OutboundEnabled=false`. Confirm the rule order (L9).
5. Set `RuleEnabled=true`, then set `EnableMx=true` on the domain stack. Inbound mail now flows; replies are evaluated but not sent. Run L8 and L9 now, to confirm the existing rules still work.
6. Run L0 and L1. **Gate:** do not continue until the spoof test L1 is dropped and the genuine reply in L0 passes all checks.
7. Set `OutboundEnabled=true`. Run L2 to L7 and L10.
8. After a clean week, raise DMARC to `p=quarantine`.

### Rollback

1. Set `OutboundEnabled=false` to stop replies immediately while keeping inbound.
2. Set `RuleEnabled=false` to stop the relay entirely, or set `EnableMx=false` to stop mail reaching SES for that domain.
3. Delete the `relay.yml` stack if needed. The bucket and table are retained, so stored mail and tokens survive the deletion. Because their names are fixed, a new stack cannot be created while they exist: delete them, losing the tokens, or import them into the new stack.
4. Compare the rule set with the snapshot from rollout step 3. The two existing rules are never edited at any step.

## 19. Known limits

- **The private address in a body or signature is not caught.** The relay rewrites headers only. An optional, off-by-default scrub (`ScrubBody=true`) can replace exact occurrences of `PRIVATE_ADDRESS` in decoded `text/plain` and `text/html` parts and re-encode only those parts. It is not promised: quoted-printable splits, HTML entities, images, quoted attributions, and attached `message/rfc822` parts can still carry the address.
- **Direct recipients leak.** If you add an ordinary To or Cc address next to the reply address, your provider delivers that copy straight from the private address; the relay never sees it. Only reply addresses and the compose form may be used as recipients.
- **Body metadata can name the provider.** MIME boundary strings, Content-ID values, HTML class names (for example Gmail's quote classes), and quoted "On ... wrote:" lines in the body pass through unchanged.
- **SES is visible.** Correspondents can see that mail passed through SES (Message-IDs and DKIM). Only the private inbox and its provider are hidden.
- **One correspondent per token.** No group threads.
- **Compose targets** are limited by the 64-octet local part.
- **Date** on forwards shows relay time, because SES overrides it.
- **A forward the private provider bounces** is visible only in the logs.
- **Trust in the provider.** The relay trusts the private inbox's provider not to let another account sign mail as `PRIVATE_ADDRESS`.

## 20. Unverified claims and open questions

| Claim | What would settle it |
|---|---|
| The SES on-wire Message-ID has the API `MessageId` before `@` | Settled on real mail: the form is `<MessageId@email.amazonses.com>`, and the anchor matched on a correspondent's reply |
| `ses:SendRawEmail` alone authorizes an SESv2 raw send | Settled on real mail: forwards, a relayed reply and the role's conditions all worked with only that action |
| SES's Authentication-Results authserv-id is `amazonses.com` with `header.i=@<domain>` | Settled by observation, not by documentation: a message from the private inbox, stored by SES, carried `amazonses.com; spf=...; envelope-from=...; helo=...; dkim=pass header.i=@<domain>; dmarc=pass header.from=<domain>;`. The parser fails closed on any other form |
| Stop scope on a message addressed to both a support address and an alias | Live test L10 |
| Vacation responders honor `Auto-Submitted: auto-forwarded` | Live test L4 |
| Some mail systems fold the case of local parts | Nothing; the relay lowercases recipients either way |
| Large providers sign `To` | Settled for the deployed inbox (Google Workspace): its signature's `h=` tag lists `to` twice and lists `cc` on a message with no Cc header, so neither field can be added. Other providers remain unverified |
| Large providers refuse to sign another account's From address | Live test L1, second part |
| How SES counts receiving chunks for messages under 256 KB | The first bill |
| A 38 MiB message fits the 40 MB send limit | Live test L6 |
| The topmost Authentication-Results header is SES's | Observed on that same message: SES's header came before every header the sender supplied. Not documented |
| Consumer Gmail and iCloud sign with aligned DKIM | Section 0 check. A Google Workspace domain does so once its own DKIM key is turned on (observed) |
| S3 storage price | The S3 pricing page |
| The account's SES pricing plan | The billing console |
| Lambda memory sufficient for a 38 MiB message | Live test L6 |
| Gmail shows the forward's `Name (local at domain)` display name once the send call carries it (section 23 item 17), and files such forwards outside spam | Settled on one real forward: Gmail showed the name and filed it in the inbox. The first forward of the day, sent before that change, went to spam; why is not known |
| The AWS CLI output shapes `tests/test_check.py` uses for a sandboxed account, an unverified or address identity, leftover resources that exist, a failed stack, and a Lambda limit too low | A read-only run of `scripts/check.py` against such an account. Seen on a real account with AWS CLI 2.38 in `us-east-1`: production access, a verified domain identity, an active rule set, a healthy existing stack, the not-found errors for a missing stack, bucket, table and identity, and, in a region with no rule set, an empty answer with exit 0 from `describe-active-receipt-rule-set` and an empty `RuleSets` list |
| Removing `After` from an existing receipt rule on a stack update moves the rule to first position | Not documented. Preview an existing stack's first update with a no-execute change set, and pass `AfterRule` to keep its position |
| The GitHub Actions workflow runs as written, and Python 3.9 is available on its runner | Its first run after a push |
| SES in regions other than us-east-1 writes its Authentication-Results header in the form the reply check expects | A dry-run reply on a deployment in that region |
| Per-rule recipient limit (quotas page says 500, walkthrough says 100) | Creating a rule with more than 100 recipients in a test rule set |

Open questions for later, none blocking: whether to add a CloudWatch alarm (needs SNS), whether spam GRAY should be forwarded with a header (chosen) or quarantined, and how to pick a non-default alias when composing from a label that names no alias.

## 21. Implementation steps

Each step names the file and symbol, the change, and an estimate in lines with a confidence band.

1. `relay-domain.yml:EmailIdentity,DkimRecords,MailFrom,Dmarc,InboundMx`: create the SES identity with Easy DKIM and MAIL FROM, the three DKIM CNAMEs, the MAIL FROM MX and SPF, DMARC `p=none`, and the MX behind `EnableMx`, for domains with no SES identity yet. (90, medium)
2. `relay.yml:Parameters`: declare the parameters in section 13. (30, high)
3. `relay.yml:MailBucket,MailBucketPolicy`: encrypted, private, versioning off, `raw/` expiry, SES put pinned to `relay-inbound`. (45, high)
4. `relay.yml:RelayTable`: on-demand, key `pk`, TTL `expires`, Retain. (15, high)
5. `relay.yml:RelayLogGroup,RelayRole`: 30-day log group and the role in section 12. (60, medium)
6. `relay.yml:RelayFunction`: Python 3.12, 1024 MB, 120 s, reserved concurrency 2, environment from parameters, `ZipFile` placeholder. (25, high)
7. `relay.yml:SesInvokePermission,RelayReceiptRule`: permission pinned to the rule ARN; rule `After: helpdesk-inbound` with S3, Lambda Event, Stop. (40, high)
8. `src/relay.py:valid_address,split_message,header_groups`: address validation, header and body split, and header grouping, ported from the support forwarder. (60, high)
9. `src/relay.py:handler,process`: per record and matched recipient, verdicts, size cap, routing (section 6), one log line. (60, medium)
10. `src/relay.py:authenticate_operator`: the eight conditions in section 8, parsing only the topmost Authentication-Results. (55, medium)
11. `src/relay.py:is_own_output,is_auto_generated,inbound_verdict`: the predicates in section 6, "Loop and abuse defenses". (30, high)
12. `src/relay.py:get_or_mint_token,lookup_token,claim,release`: token items and send claims. (60, medium)
13. `src/relay.py:wrap,unwrap,translate_ids`: section 7 wrapping, unwrapping, and the `o#` anchor. (50, medium)
14. `src/relay.py:rewrite_inbound,rewrite_outbound,parse_compose`: section 5 tables, single-occurrence collapse, header guard, and section 9 grammar. (120, medium)
15. `src/relay.py:send,notify_operator`: SESv2 raw send with one SDK attempt, post-send anchor write, notices. (35, high)
16. `scripts/render.py`, `scripts/deploy.sh`: splice the source into the template, expand the comma-list parameters into per-domain rule recipients and IAM statements (expanding at render time keeps the templates free of transforms), and deploy in rollout order. (80, medium)
17. `tests/test_relay.py`, `tests/fixtures/*.eml`: unit tests U1 to U18. (350, medium)
18. `README.md`: parameters, deploy order, compose convention, limits, replay, rollback. (100, high)

Total: about 1,300 lines including tests and docs, in 7 files plus fixtures. New moving parts beyond the existing pattern: one DynamoDB table.

Overall confidence: medium. It would rise to high after a live reply from the real private inbox shows SES's Authentication-Results with an aligned `dkim=pass` (L0) and the four-message thread holds on both sides (L3).

## 22. Sources

- SES quotas: https://docs.aws.amazon.com/ses/latest/dg/quotas.html
- SES receipt notification contents (verdicts, recipients): https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html
- SES Lambda action (no body in event): https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-lambda.html
- SES S3 action: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-s3.html
- SES receipt rules walkthrough (plus-label matching, one active set): https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html
- SES email receiving concepts (unmatched recipients rejected, Authentication-Results): https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html
- SES MX record: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-mx-record.html
- SES header fields (Message-ID and Date overridden, single-occurrence fields): https://docs.aws.amazon.com/ses/latest/dg/header-fields.html
- SES raw sending: https://docs.aws.amazon.com/ses/latest/dg/send-email-raw.html
- SESv2 RawMessage: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_RawMessage.html
- SESv2 SendEmail: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html
- SES attachments: https://docs.aws.amazon.com/ses/latest/dg/attachments.html
- SES email feedback notifications: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity-using-notifications-email.html
- SES ReceiptRule API: https://docs.aws.amazon.com/ses/latest/APIReference/API_ReceiptRule.html
- Controlling access to SES (condition keys): https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html
- CloudFormation ReceiptRule: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-receiptrule.html
- CloudFormation EmailIdentity: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-emailidentity.html
- CloudFormation Lambda Code (ZipFile 4 MB): https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-code.html
- Lambda asynchronous error handling: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html
- DynamoDB TTL: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
- SES pricing: https://aws.amazon.com/ses/pricing/
- Lambda pricing: https://aws.amazon.com/lambda/pricing/
- DynamoDB on-demand pricing: https://aws.amazon.com/dynamodb/pricing/on-demand/
- RFC 5321: https://www.rfc-editor.org/rfc/rfc5321.html
- RFC 5322: https://www.rfc-editor.org/rfc/rfc5322
- Gmail threading changes: https://workspaceupdates.googleblog.com/2019/03/threading-changes-in-gmail-conversation-view.html
- Lambda Python runtime: https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html
- SES MAIL FROM domain: https://docs.aws.amazon.com/ses/latest/dg/mail-from.html
- SES receiving permissions: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html
- CloudFormation ReceiptRule Rule property: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ses-receiptrule-rule.html
- SES suppression list: https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html
- S3 pricing: https://aws.amazon.com/s3/pricing/

## 23. Build notes: where the code departs from this document

The first build covers one alias on a domain that already has an SES identity, inbound MX, and DNS records. Each departure below is deliberate.

1. **`relay-domain.yml` and `scripts/deploy.sh` are not built** (section 17, steps 1 and 16). The deployed domain needs no identity or DNS work, and deploying is one command, documented in `README.md`.
2. **One alias and one domain per stack.** `Alias` and `Domain` are single strings, so the template needs no list handling and `scripts/render.py` only splices the function source into the template. The function still reads a comma list of aliases from its environment.
3. **The inbound drop rule is narrower than section 6 states.** Section 6 drops inbound mail whose From, Reply-To, or envelope sender is any relay-domain address. On a domain that other mailboxes share, that would silently drop their mail to the alias. The code drops only the relay's own addresses: an alias (with or without a `+label`), `reply@` and `reply+...@`, `relay@`, and the private address. The same test refuses reply peers and compose targets.
4. **The sender check is stricter than section 8, condition 3.** The topmost Authentication-Results value must begin with the exact identifier `amazonses.com`, must contain no quoted string, backslash, control character, or nested or unbalanced comment, and every entry must be made of `key=value` tokens from a fixed character set. Its final entry must be `dmarc=pass header.from=<private domain>`, and every `dkim=` entry in it must be a pass aligned with the private domain. The reason: that header also carries values the sender chooses (the envelope sender and the HELO name), which come before SES's own DKIM and DMARC results. A forged entry cannot be the last one, and with `dkimVerdict` PASS at least one `dkim=` entry is SES's own, so a forged aligned entry cannot stand beside a real signature for another domain. Every `header.i` and `header.d` in a `dkim=` entry must be aligned. A result (`spf=`, `dkim=`, `dmarc=`) may only be the first token of an entry, and exactly one `dmarc=` entry may appear. Only one comment is accepted, and only inside the first entry, where SES puts its SPF explanation; any other parenthesis fails the check, so an entry cannot be hidden in a comment. Consequences: the private inbox's domain must publish a DMARC record, even `p=none` (section 8 would have accepted a domain with none), and a provider that adds a second signature for a different domain has every reply refused. **Unverified:** whether SES can ever write a space, a `;`, or a parenthesis inside the HELO or envelope-sender value. The checks above are built so that none of those lets a forged entry pass, but they have only been tested against crafted values, not against SES.
5. **More header checks before a reply is trusted.** A message with more than one From, Sender, To, or Cc header field is refused, and so is an envelope sender that is not a plain address. The From and Sender values are read from the raw header under a strict single-mailbox grammar (a bare address, or an optional quoted or atom-only name followed by one address in angle brackets), because the standard library's header parsing treats forms such as `a@x <b@y>` differently between Python releases: a build that used the parsed value relayed such a message on 3.9 and 3.12 and refused it on 3.14. A name with a comment, or any other form, is refused.
6. **A reply or new message without exactly one Message-ID header field holding exactly one id is refused with a notice,** because the send claim is keyed on it. The id is read from the raw header value and must be printable ASCII of at most 512 bytes.
7. **Tests use `unittest` with fake AWS clients and inline messages,** not `pytest` and `.eml` fixtures. They pass on Python 3.12, the Lambda runtime, and on 3.9 and 3.14.
8. **The header guard also reads decoded values, on a bounded block.** A reply whose outgoing header block is over 16,384 bytes is refused with a notice before anything is decoded. Below that, the guard checks the literal bytes with backslashes removed (so a quoted pair hides nothing), the percent-decoded bytes, the encoded words, and every kept header as the standard library parser decodes it, parameters included (RFC 2047 and RFC 2231 forms). It also joins continued parameters (`name*0`, `name*1`) by hand, whatever their letter case, spacing, numbering gaps, or header, because a lenient mail client could reassemble forms the parser does not. This is the only place the standard library header parser runs; it runs once per message, and any error it raises refuses the reply. The guard cannot promise to catch every encoding a client might invent. Known forms it does not catch, none of which a real mail client was shown to produce: an encoded word split across two continued segments, a duplicated segment number, UTF-7 continued parameters, an unquoted parameter mixing an encoded word with plain text, and `name* 0=` with a space after the star.
9. **Notices are sent in dry run, and at most once per message and reason.** Section 8 says nothing is sent with `OutboundEnabled=false`; the build relays nothing but still tells the operator why an authenticated message was refused. Each notice takes its own claim, so a retried event does not repeat it. A notice that cannot be sent, for a retryable or a permanent reason, releases its claim and raises on every path, so Lambda delivers the event again and a message is never recorded as handled when the operator was not told. For a notice about a permanently rejected message the send claim is released too, and the send is tried again with it.
10. **Access-denied, account-suspended, sending-paused, expired-credential, request-timeout, and signature send errors are retried, not treated as permanent,** so a missing IAM permission (the unverified claim in section 12) or a sending pause does not consume messages. Lambda still gives up after its retries; the raw copy stays in the bucket.
11. **The header and body are split at the first blank line,** with LF or CRLF endings in any mix. A message with no blank line is treated as headers with an empty body.
12. **Header text is bounded before anything reads it.** A message whose header block is over 262,144 bytes is not processed: the operator gets an `oversize-headers` notice, whoever sent it. Otherwise the relay reads only the first occurrence of From, Reply-To, Sender, To, Cc, Subject, References, In-Reply-To, Message-ID, Auto-Submitted, Precedence, List-Id and Content-Type, as unfolded plain text, and only when the field is at most 8,192 bytes on the wire, counting two bytes for each line ending (CRLF assumed, so a field with bare LF endings is cut off slightly earlier). A message whose header block contains a bare CR or a control character (other than tab) is not processed either: mail software disagrees on where such a header ends, so the operator gets a `malformed-headers` notice and nothing is interpreted. A header whose name contains a non-ASCII byte is not one of these fields. A second From, Reply-To or Sender header makes that field unusable, so the correspondent is then taken from the next source in order (Reply-To, From, envelope sender). The sender check and the loop marker also read From, Sender, Message-ID, Authentication-Results and X-Relay-Hop from the raw header lines, under their own limits (1,000 characters for From and Sender, 512 bytes for a Message-ID). A larger field still passes through on the inbound leg, but for choosing the correspondent, the informational To and Cc copies, the loop refusals and threading it counts as absent; a later occurrence of the same field is never used in its place. Field text is read as UTF-8, so an unencoded non-ASCII display name is shown correctly; bytes that are not UTF-8 are replaced. An internationalised domain is normalised before the address is tested. Display names are decoded from encoded words after the address list is split. An encoded word that holds a comma (non-compliant, but some clients write it) therefore splits the field into two entries, the field has no single address, and the correspondent falls back to the next source in order (From after Reply-To, then the envelope sender). A display name can also come from a trailing comment, as in `bob@example.org (Bob Smith)`. An address the parser joins across whitespace or a fold, such as `a@b.example .evil.example`, is stored as the parser reports it. A decoded name that contains a character that cannot be sent is shown with a replacement character. A From or Sender longer than 1,000 characters never passes the sender check. A Message-ID longer than 512 bytes is left out of the threading headers on the inbound leg, and a reply carrying one is refused with a notice. Rewriting happens before the send claim is taken.
13. **Inbound mail is dropped when any address in From or Reply-To, or the envelope sender, is one of the relay's own,** with one exception: mail whose From or envelope sender is an alias (with or without a `+label`) and whose Reply-To is a single valid address that is not one of the relay's own is forwarded, with that Reply-To as the correspondent. Website contact forms send exactly that. Mail From the alias with no usable Reply-To (none, two headers, or more than one address) is not forwarded, because there is nobody to answer, and is not dropped silently: the operator gets a `no-reply-to` notice. Mail whose From header mentions the private address as a whole address, however malformed the header, is dropped whatever its Reply-To, and so is mail From `reply` or `relay`. Only parsed addresses are tested, so one of the relay's own addresses inside a display name or a comment does not make a message the relay's own. The chosen correspondent is tested once more after its domain is normalised, so no token is ever stored for the private address or one of the relay's own. A relayed reply that comes back to the alias with its marker stripped and an outside Reply-To added is forwarded once to the private inbox, like any other form mail; with the marker it is dropped. A malformed From that the parser reads differently from a human, such as `a@x <b@y>`, may be forwarded under whichever address the parser reports; it cannot loop, because relay output is marked, and it cannot be replied to as an own address. A message with no usable sender at all (no single valid address in Reply-To or From, and no envelope sender) is not dropped silently: the operator gets a notice.
14. **Known limit of the threading translation.** The reply path passes on any Message-ID that has the wrapped form, so the operator's own mail client could craft one. When the anchor for a relayed reply is missing, the SES Message-ID of that reply is wrapped and returned to the correspondent who already received it. Neither case discloses a provider Message-ID that the operator's client sent unwrapped.
15. **Smaller differences.** The token lookup key lowercases the correspondent's address, so two addresses differing only in case share a token. The IAM role has a generated name, not `mailrelay`. An event with no relay-domain recipient writes one log line, not one per recipient. No `error` outcome line is written; a raised error appears as the runtime's own traceback. A notice is logged as `notice:<reason>`, not as a bare `notice`. The forward's display name never contains an `@`: the correspondent is written `local at domain`, alone when the sender has no display name (or one that is just the address) and in parentheses after the name otherwise. This is a precaution, not a response to an observed problem: a display name holding an address other than the header's real one is a common spoofing sign. An earlier version of this note said Gmail had been seen hiding such a name. That was a misreading: the name was missing because of the send call described in item 17. Any `@` in the sender's own name, and the look-alikes U+FF20 and U+FE6B, are replaced the same way, control characters, backslashes and double quotes in the name become spaces, and an encoded word in the final text is broken up (`=?` becomes `= ?`, in the correspondent's local part too). That stops a mail client from decoding one into an address under the readers tested: a strict reader, one that decodes inside quotes, one that drops backslashes and control characters, and one that collapses whitespace. A reader that deletes all whitespace, strips zero-width characters, or normalises full-width punctuation could still rebuild one from a crafted name. A non-ASCII name is written as folded encoded words of at most 75 characters. A plain-text name stays on one line, at most about 570 characters plus the relay domain's length, under the 998-character limit. On real mail, Gmail showed a name in this form. The name is cut at 70 characters after that replacement and before the correspondent is added, so the correspondent is never cut. The header guard also checks percent-decoded and encoded-word forms anywhere in the outgoing header block. Property names in SES's Authentication-Results are matched without regard to case. Not handled, because SES puts its own headers first: a stored message that begins with a blank line.
16. **Not built:** the optional body scrub (`ScrubBody`), the display name stored with a token, and the notice for a compose address whose local part exceeds 64 octets.
17. **The send call carries the whole From header value.** SES uses the `FromEmailAddress` parameter of its send call as the From of the message and writes it over the From header inside the raw message. Observed on delivered mail: with a bare address in that parameter, forwards arrived with no display name although the raw message carried one. The relay therefore passes the unfolded value of the From header it generated, display name included, for forwards, relayed replies and notices. The IAM conditions on `ses:FromAddress` are unchanged; whether SES evaluates them on the address part of a value with a display name is shown by the account's older forwarder, which sends that way. **Unverified:** any length limit SES puts on that parameter; a long encoded name is the case to watch.
18. **The rule set and the rule's position are template parameters.** `RuleSetName` (default `default-rule-set`) names the active receipt rule set, and `AfterRule` (default empty, which places the rule first) names the rule to follow. Both SES grants are pinned to `relay-inbound` in the named set. The stack still never creates or activates a rule set. A stack created before these parameters existed must pass `AfterRule` with the name of the rule it currently follows on its first update with this template, or the empty default applies; changing `RuleSetName` replaces the rule.
19. **A read-only preflight check replaces the per-domain template and the deploy script.** `scripts/check.py` makes only read-only calls. It never suggests activating a rule set unless it has confirmed that none is active or that none exists, and for an existing stack it prints an update command that leaves replies as they are. Where it must tell an absent thing from an unreadable one (the stack, leftover resources, the SES identities), only an AWS not-found error code counts as absent, and any other failure is reported as unreadable. A failed read of the Lambda limit is skipped without a verdict. It looks at the account, its Lambda concurrency limit, the relay domain's SES identity, the active rule set and any rule that already matches the alias or domain, an existing or failed stack, leftover resources with the relay's fixed names, and, when `dig` is installed, the domain's MX and the inbox domain's DMARC record (a record found only on a parent domain is a note, since the script cannot tell which parent is the registered domain). It prints what to fix and the deploy command. It cannot see whether the inbox's provider signs with the inbox's own domain; the README keeps that as a manual step. Domain setup is documented as commands in the README, which work with any DNS host.
20. **The SES sandbox is untested.** Forwards should work there once the private inbox is a verified identity, though the role grants sending on the relay domain's identity only, and SES may also require permission on the recipient's identity in the sandbox; one forward on a sandboxed account settles it. Replies to correspondents need production access.
