#!/usr/bin/env python3
"""Checks an AWS account before the relay is deployed, and prints the deploy command.

Read-only: it runs `aws` describe, get, head and list calls, and `dig` when it is installed.
It changes nothing. Each line it prints is "ok", "fix" (do this before deploying) or "note".
"""
import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys

STACK = "mailrelay"
RULE = "relay-inbound"
ALIAS = re.compile(r"^[a-z0-9._-]+@[a-z0-9.-]+$")
INBOX = re.compile(r"^[^@\s]+@[a-z0-9.-]+$")
HEALTHY = ("CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE")
MISSING = ("404", "NotFoundException", "ResourceNotFoundException")  # AWS error codes for an absent thing
ERROR = re.compile(r"An error occurred \((\w+)\) when calling the \w+ operation(?:: (.*))?", re.S)


def run_command(args):
    """(exit code, output, error text) of one command."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, errors="replace")
    except OSError:  # the command is not installed
        return 127, "", "not installed"
    return done.returncode, done.stdout, done.stderr


def listed(value):
    """The dict items of a JSON list; anything else counts as empty."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


class Check:
    def __init__(self, region, domain, alias, inbox, run=run_command, has_dig=None):
        self.region, self.domain, self.alias, self.inbox = region, domain, alias, inbox
        self.run = run
        self.has_dig = shutil.which("dig") is not None if has_dig is None else has_dig
        self.lines, self.rule_set, self.after, self.exists, self.has_rule = [], "", "", False, False
        self.error = ""

    def say(self, status, text):
        self.lines.append((status, text))

    def aws(self, *args):
        """(answered, data) for one AWS CLI call. A failed call is (False, {}) and its error text is
        kept in self.error; data is always a dict."""
        code, out, self.error = self.run(["aws", *args, "--region", self.region, "--output", "json"])
        if code != 0:
            return False, {}
        try:
            data = json.loads(out) if out.strip() else {}
        except (ValueError, RecursionError):
            return False, {}
        return True, data if isinstance(data, dict) else {}

    def gone(self):
        """True when the last failed call said the thing does not exist, not that it could not be read."""
        found = ERROR.search(self.error)  # the code, never a search of the text: an ARN can hold "404"
        if not found:
            return False
        code, message = found.group(1), found.group(2) or ""
        return code in MISSING or (code == "ValidationError"
                                   and message.strip().startswith(f"Stack with id {STACK} does not exist"))

    def dig(self, kind, name):
        """Record values, or None when dig did not answer."""
        code, out, _ = self.run(["dig", "+short", kind, name])
        # Lines starting with ";" are dig's own comments, such as a retry notice.
        values = [line.strip().strip('"').strip() for line in out.splitlines() if not line.lstrip().startswith(";")]
        return [value for value in values if value] if code == 0 else None

    def arguments(self):
        ok = True
        if not ALIAS.match(self.alias) or not self.alias.endswith("@" + self.domain):
            self.say("fix", f"The alias must be a lowercase address at {self.domain}.")
            ok = False
        if not INBOX.match(self.inbox):
            self.say("fix", "The inbox must be an address whose domain is written in lowercase.")
            ok = False
        elif self.inbox.rsplit("@", 1)[-1] == self.domain:
            self.say("fix", "The inbox must not be on the relay domain: its mail would come back to the relay.")
            ok = False
        return ok

    def account(self):
        answered, identity = self.aws("sts", "get-caller-identity")
        if not answered or not identity.get("Account"):
            self.say("fix", "The AWS CLI cannot reach your account. Run `aws configure`, then run this again.")
            return None
        self.say("ok", f"AWS account {identity['Account']}, region {self.region}.")
        return identity["Account"]

    def sending(self):
        answered, account = self.aws("sesv2", "get-account")
        if not answered:
            self.say("fix", f"SES did not answer in {self.region}. Check your permissions, and that SES receives "
                            "mail in this region.")
            return
        if account.get("ProductionAccessEnabled"):
            self.say("ok", "SES production access is on: the relay can send replies to anyone.")
            return
        self.say("note", "SES is in the sandbox here, which this relay has not been tried in. Forwards should work "
                         "once your inbox is a verified identity. Replies to correspondents need production "
                         "access: request it in the SES console before you switch replies on.")
        unread, pending = False, ""
        for identity in (self.inbox, self.inbox.rsplit("@", 1)[-1]):
            answered, found = self.aws("sesv2", "get-email-identity", "--email-identity", identity)
            if answered and found.get("VerifiedForSendingStatus"):
                self.say("ok", f"{identity} is a verified identity, which sandbox sending needs.")
                return
            unread = unread or (not answered and not self.gone())
            pending = pending or (identity if answered else "")
        if pending:
            self.say("fix", f"{pending} is an SES identity but is not verified yet. Open the link SES mailed to it "
                            "(or, for a domain, finish its DKIM records), then run this again.")
        elif unread:
            self.say("fix", "Could not read whether your inbox is a verified SES identity (permissions or "
                            "throttling). Run this again.")
        else:
            self.say("fix", "Verify your inbox for the sandbox, then open the link SES mails you: aws sesv2 "
                            f"create-email-identity --email-identity {shlex.quote(self.inbox)} --region {self.region}")

    def concurrency(self):
        # A new stack reserves 2 concurrent executions, and Lambda keeps 100 unreserved for other functions.
        answered, settings = self.aws("lambda", "get-account-settings")
        limit = settings.get("AccountLimit") if isinstance(settings.get("AccountLimit"), dict) else {}
        free = limit.get("UnreservedConcurrentExecutions")
        if answered and isinstance(free, int) and free - 100 < 2:
            self.say("fix", f"This account's Lambda concurrency limit leaves {free} unreserved, and Lambda keeps 100 "
                            "of those back, so the stack cannot reserve the 2 it asks for and the deploy would "
                            "fail. Ask for a higher \"Concurrent executions\" limit under Lambda in the Service "
                            "Quotas console.")

    def identity(self):
        create = f"aws sesv2 create-email-identity --email-identity {self.domain} --region {self.region}"
        answered, found = self.aws("sesv2", "get-email-identity", "--email-identity", self.domain)
        if not answered and not self.gone():
            self.say("fix", f"Could not read the SES identity for {self.domain} (permissions, throttling or "
                            "region). Run this again.")
        elif not answered:
            self.say("fix", f"{self.domain} has no SES identity. Create one, then publish the DKIM records it "
                            f"returns: {create}")
        elif found.get("IdentityType", "DOMAIN") != "DOMAIN":
            self.say("fix", f"{self.domain} must be a domain identity in SES, not an address identity. Create it: {create}")
        elif not found.get("VerifiedForSendingStatus"):
            self.say("fix", f"{self.domain} is not verified in SES yet. Publish its DKIM records and wait: aws sesv2 "
                            f"get-email-identity --email-identity {self.domain} --region {self.region}")
        else:
            self.say("ok", f"{self.domain} is a verified SES domain identity.")

    def rules(self):
        answered, active = self.aws("ses", "describe-active-receipt-rule-set")
        metadata = active.get("Metadata") if isinstance(active.get("Metadata"), dict) else {}
        name = metadata.get("Name")
        if not name:
            read, sets = self.aws("ses", "list-receipt-rule-sets")
            # An answer without a RuleSets list is not proof that no set exists.
            known = read and isinstance(sets.get("RuleSets"), list)
            names = [str(item["Name"]) for item in listed(sets.get("RuleSets")) if item.get("Name")]
            # With no set at all, creating and activating one cannot switch another off.
            if known and sets["RuleSets"] == [] and not sets.get("NextToken"):
                self.say("fix", "This region has no receipt rule set. Create one and activate it:\n"
                                f"      aws ses create-receipt-rule-set --rule-set-name relay --region {self.region}\n"
                                f"      aws ses set-active-receipt-rule-set --rule-set-name relay --region {self.region}")
            elif answered and names:
                self.say("fix", f"Rule sets exist here ({', '.join(names)}) but none is active, so "
                                "SES acts on no incoming mail. Activate the one you want: aws ses "
                                f"set-active-receipt-rule-set --rule-set-name NAME --region {self.region}")
            else:
                # Never suggest activating a set here: that would switch off one that may be live.
                self.say("fix", "Could not read the active receipt rule set (permissions, throttling or region). "
                                "Nothing was assumed. Run this again.")
            return
        rules = [rule for rule in listed(active.get("Rules")) if isinstance(rule.get("Name"), str)]
        names = [rule["Name"] for rule in rules]
        self.rule_set, self.has_rule = name, RULE in names
        if RULE in names:  # keep the relay's rule where it is
            self.after = names[names.index(RULE) - 1] if names.index(RULE) else ""
        else:
            self.after = names[-1] if names else ""
        self.say("ok", f"Active receipt rule set: {name}." + (f" The relay's rule follows {self.after}."
                                                               if self.after else " The relay's rule comes first."))
        wanted = (self.alias, f"reply@{self.domain}", self.domain)
        for rule in rules:
            if rule["Name"] == RULE or rule.get("Enabled") is False:
                continue
            given = rule.get("Recipients")
            recipients = [str(recipient).lower() for recipient in (given if isinstance(given, list) else [])]
            if not recipients or any(recipient in wanted or (recipient.startswith(".") and self.domain.endswith(recipient))
                                     for recipient in recipients):
                self.say("fix", f"The rule {rule.get('Name')} already receives mail for this alias or domain, so "
                                "both rules would act on the same message. Use another domain or a subdomain, "
                                "or change that rule's recipients.")

    def stack(self, account):
        answered, found = self.aws("cloudformation", "describe-stacks", "--stack-name", STACK)
        stacks = listed(found.get("Stacks"))
        if not answered and not self.gone():
            self.say("fix", f"Could not read the stack {STACK} (permissions, throttling or region). Run this again.")
            return
        if stacks:
            status = str(stacks[0].get("StackStatus", ""))
            if status in HEALTHY:
                self.exists = True
                self.say("note", f"The stack {STACK} already exists ({status}). The command below updates it and "
                                 "leaves its other settings, such as whether replies are on, as they are.")
            elif status == "ROLLBACK_COMPLETE":
                self.say("fix", "An earlier deploy failed and left an empty stack. Delete it first: "
                                f"aws cloudformation delete-stack --stack-name {STACK} --region {self.region}")
            else:
                self.say("fix", f"The stack {STACK} is in state {status}. Resolve that in the CloudFormation "
                                "console before deploying.")
            return
        if self.has_rule:
            self.say("fix", f"The rule {RULE} is in the active rule set, but no stack named {STACK} was found in "
                            "this region. A relay may be running from a stack with another name. Nothing was "
                            "assumed; find that stack before deploying.")
            return
        leftovers, unread = [], []
        for label, call in (
            (f"bucket {STACK}-{account}-{self.region}", ("s3api", "head-bucket", "--bucket", f"{STACK}-{account}-{self.region}")),
            (f"table {STACK}", ("dynamodb", "describe-table", "--table-name", STACK)),
        ):
            if self.aws(*call)[0]:
                leftovers.append(label)
            elif not self.gone():
                unread.append(label)
        read, groups = self.aws("logs", "describe-log-groups", "--log-group-name-prefix", f"/aws/lambda/{STACK}")
        if any(group.get("logGroupName") == f"/aws/lambda/{STACK}" for group in listed(groups.get("logGroups"))):
            leftovers.append(f"log group /aws/lambda/{STACK}")
        elif not read:
            unread.append(f"log group /aws/lambda/{STACK}")
        if leftovers:
            table = (" The table holds your reply addresses, so deleting it breaks replies to old forwards."
                     if f"table {STACK}" in leftovers else "")
            self.say("fix", "Left over from an earlier stack, and they block a new one: " + ", ".join(leftovers)
                            + "." + table + " See \"Removing it\" in the README.")
        elif unread:
            self.say("fix", "Could not check for leftovers from an earlier stack (" + ", ".join(unread)
                            + "): permissions or throttling. Run this again.")
        else:
            self.say("ok", f"No stack named {STACK} and nothing left over from one.")

    def dns(self):
        inbox_domain = self.inbox.rsplit("@", 1)[-1]
        labels = inbox_domain.split(".")
        parents = [".".join(labels[index:]) for index in range(len(labels) - 1)]
        target = f"inbound-smtp.{self.region}.amazonaws.com"
        expect = (f"      MX   {self.domain}   10 {target}\n"
                  f"      TXT  _dmarc.{inbox_domain}   a record starting v=DMARC1")
        if not self.has_dig:
            self.say("note", "dig is not installed, so look these records up with any DNS lookup tool:\n" + expect)
            return
        found = self.dig("MX", self.domain)
        if found is None:
            self.say("note", "dig did not answer, so look these records up yourself:\n" + expect)
            return
        hosts = [line.split()[-1].rstrip(".").lower() for line in found]
        hosts = [host for host in hosts if host]  # "0 ." is a null MX: the domain receives no mail
        if hosts == [target]:
            self.say("ok", f"{self.domain} delivers its mail to SES in {self.region}.")
        elif not hosts:
            self.say("note", f"{self.domain} has no MX record yet. Add it after the stack exists, because it is "
                             f"the switch that sends mail to SES:  {self.domain}  MX  10 {target}")
        else:
            self.say("fix", f"{self.domain} already receives mail at {', '.join(hosts)}. Pointing its MX at SES "
                            "would move all of that mail to the relay, which accepts only the alias. Use a "
                            f"subdomain for the relay instead, for example r.{self.domain}.")
        answers = [(name, self.dig("TXT", f"_dmarc.{name}")) for name in parents]
        has = [name for name, records in answers if any(r.lower().startswith("v=dmarc1") for r in records or [])]
        if inbox_domain in has:
            self.say("ok", f"{inbox_domain} publishes a DMARC record, which the reply check needs.")
        elif has:
            self.say("note", f"{inbox_domain} has no DMARC record of its own; {has[0]} publishes one. That covers "
                             f"your inbox only if {has[0]} is the registered domain it belongs to.")
        elif any(records is None for _, records in answers):
            self.say("note", f"dig did not answer for _dmarc.{inbox_domain}. The reply check needs a DMARC record "
                             "there or on its registered domain; look it up yourself.")
        else:
            self.say("fix", f"{inbox_domain} publishes no DMARC record, so every reply would be refused. Add: "
                            f"_dmarc.{inbox_domain}  TXT  \"v=DMARC1; p=none\"")

    def command(self):
        values = [f"Domain={self.domain}", f"Alias={self.alias}", f"PrivateAddress={self.inbox}",
                  f"RuleSetName={self.rule_set}", f"AfterRule={self.after}"]
        if not self.exists:  # a first deploy starts with replies off; an update keeps what is set
            values.append("OutboundEnabled=false")
        quoted = [shlex.quote(value) for value in values]
        return (
            "python3 scripts/render.py\n"
            f"aws cloudformation deploy --region {self.region} --stack-name {STACK} \\\n"
            "  --template-file build/relay.yml --capabilities CAPABILITY_IAM \\\n"
            f"  --parameter-overrides {' '.join(quoted[:2])} \\\n"
            f"    {' '.join(quoted[2:])}"
        )

    def report(self):
        if self.arguments():
            account = self.account()
            if account:
                self.sending()
                self.identity()
                self.rules()
                self.stack(account)
                if not self.exists:  # an existing stack already holds its reservation
                    self.concurrency()
                self.dns()
        self.say("note", "Not checked here: that your inbox's provider signs your mail with your inbox's own "
                         "domain. See \"Check your inbox\" in the README.")
        fixes = sum(1 for status, _ in self.lines if status == "fix")
        out = [f"{status:<5}{text}" for status, text in self.lines]
        if fixes:
            out.append(f"\n{fixes} thing(s) to fix before deploying. Run this again afterwards.")
        elif self.rule_set:
            first = "Ready. Update the stack:" if self.exists else "Ready. Deploy with replies off:"
            out.append(f"\n{first}\n\n" + self.command())
        return "\n".join(out), 1 if fixes or not self.rule_set else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", required=True, help="AWS region where SES receives mail, such as us-east-1")
    parser.add_argument("--domain", required=True, help="the relay domain, lowercase")
    parser.add_argument("--alias", required=True, help="the address correspondents write to, on that domain")
    parser.add_argument("--inbox", required=True, help="your private inbox")
    options = parser.parse_args(argv)
    text, code = Check(options.region, options.domain.lower(), options.alias, options.inbox).report()
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
