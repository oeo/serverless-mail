"""Unit tests for scripts/check.py. The AWS CLI and dig are replaced by canned output."""
import importlib.util
import json
import pathlib
import shlex
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check", ROOT / "scripts" / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

REGION, DOMAIN, ALIAS, INBOX = "us-east-1", "example.com", "you@example.com", "private@example.net"
ACTIVE = "ses describe-active-receipt-rule-set"
LISTED = "ses list-receipt-rule-sets"
STACK = "cloudformation describe-stacks --stack-name mailrelay"
MX = "dig +short MX example.com"
DMARC = "dig +short TXT _dmarc.example.net"
IDENTITY = "sesv2 get-email-identity --email-identity example.com"
BUCKET = "s3api head-bucket --bucket mailrelay-123456789012-us-east-1"
TABLE = "dynamodb describe-table --table-name mailrelay"
LOGS = "logs describe-log-groups --log-group-name-prefix /aws/lambda/mailrelay"
LIMITS = "lambda get-account-settings"
DENIED = "An error occurred (AccessDenied) when calling the operation: not authorized"
# An access error whose text happens to hold every word a missing thing is reported with.
LOOKALIKE = ("An error occurred (AccessDenied) when calling the DescribeStacks operation: User: "
             "arn:aws:iam::123404567890:role/NotFoundHandler is not authorized: Not Found, does not exist")
# What the AWS CLI prints when the thing asked for does not exist.
ABSENT = {
    "cloudformation describe-stacks": "An error occurred (ValidationError) when calling the DescribeStacks operation: "
                                      "Stack with id mailrelay does not exist",
    "s3api head-bucket": "An error occurred (404) when calling the HeadBucket operation: Not Found",
    "dynamodb describe-table": "An error occurred (ResourceNotFoundException) when calling the DescribeTable operation",
    "sesv2 get-email-identity": "An error occurred (NotFoundException) when calling the GetEmailIdentity operation",
}
READY = {
    "sts get-caller-identity": {"Account": "123456789012"},
    "sesv2 get-account": {"ProductionAccessEnabled": True},
    IDENTITY: {"IdentityType": "DOMAIN", "VerifiedForSendingStatus": True},
    ACTIVE: {
        "Metadata": {"Name": "main-rules"},
        "Rules": [{"Name": "first", "Recipients": ["other.example"]}, {"Name": "second", "Recipients": ["help@example.org"]}],
    },
    LOGS: {"logGroups": []},
    LIMITS: {"AccountLimit": {"ConcurrentExecutions": 1000, "UnreservedConcurrentExecutions": 1000}},
    MX: "10 inbound-smtp.us-east-1.amazonaws.com.\n",
    DMARC: '"v=DMARC1; p=none"\n',
}
MUTATING = ("create", "delete", "put", "update", "set-", "deploy", "send", "remove", "activate")


def runner(answers, calls=None, errors=None):
    """A stand-in for the command runner: known commands succeed. Anything else fails, saying "not found"
    for the things that are normally absent and "access denied" otherwise; errors overrides that text."""
    def run(args):
        key = " ".join(args).replace(" --region us-east-1 --output json", "")
        key = key[4:] if key.startswith("aws ") else key
        if calls is not None:
            calls.append(key)
        if key in (errors or {}):
            return 1, "", errors[key]
        if key not in answers:
            return 1, "", ABSENT.get(" ".join(key.split()[:2]), DENIED)
        answer = answers[key]
        return 0, answer if isinstance(answer, str) else json.dumps(answer), ""
    return run


def report(answers, has_dig=True, alias=ALIAS, inbox=INBOX, calls=None, errors=None):
    return check.Check(REGION, DOMAIN, alias, inbox, run=runner(answers, calls, errors), has_dig=has_dig).report()


def with_rules(*rules):
    return dict(READY, **{ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": list(rules)}})


class CheckTest(unittest.TestCase):
    def test_ready_account_prints_the_deploy_command(self):
        calls = []
        text, code = report(READY, calls=calls)
        self.assertEqual(code, 0, text)
        self.assertNotIn("\nfix", "\n" + text)
        self.assertIn("Ready. Deploy with replies off:", text)
        self.assertIn("Domain=example.com Alias=you@example.com", text)
        self.assertIn("PrivateAddress=private@example.net RuleSetName=main-rules AfterRule=second OutboundEnabled=false", text)
        self.assertIn("aws cloudformation deploy --region us-east-1 --stack-name mailrelay", text)
        self.assertIn("--template-file build/relay.yml --capabilities CAPABILITY_IAM", text)
        self.assertIn("Not checked here", text)
        self.assertIn("ok   example.net publishes a DMARC record", text)
        self.assertFalse([call for call in calls if any(f" {verb}" in call for verb in MUTATING)], calls)

    def test_every_command_it_can_run_is_read_only(self):
        calls = []
        for answers in (READY, dict(READY, **{"sesv2 get-account": {}}), {k: v for k, v in READY.items() if k != ACTIVE},
                        dict(READY, **{STACK: {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}})):
            report(answers, calls=calls)
        verbs = {call.split()[1] for call in calls if not call.startswith("dig")}
        self.assertTrue(all(verb.startswith(("get-", "describe-", "list-", "head-")) for verb in verbs), verbs)
        self.assertFalse([call for call in calls if any(f" {verb}" in call for verb in MUTATING)])

    def test_sandbox_needs_a_verified_inbox_first(self):
        answers = dict(READY, **{"sesv2 get-account": {"ProductionAccessEnabled": False}})
        text, code = report(answers)
        self.assertEqual(code, 1)
        self.assertIn("sandbox", text)
        self.assertIn("create-email-identity --email-identity private@example.net", text)
        text, code = report(answers, errors={"sesv2 get-email-identity --email-identity example.net": DENIED})
        self.assertEqual(code, 1)
        self.assertIn("Could not read whether your inbox is a verified SES identity", text)
        self.assertNotIn("create-email-identity", text)
        waiting = dict(answers, **{"sesv2 get-email-identity --email-identity private@example.net":
                                   {"VerifiedForSendingStatus": False}})
        text, code = report(waiting)  # created, link not opened yet: creating it again would fail
        self.assertEqual(code, 1)
        self.assertIn("private@example.net is an SES identity but is not verified yet", text)
        self.assertNotIn("create-email-identity", text)
        answers["sesv2 get-email-identity --email-identity example.net"] = {"VerifiedForSendingStatus": True}
        self.assertEqual(report(answers)[1], 0)
        del answers["sesv2 get-email-identity --email-identity example.net"]
        answers["sesv2 get-email-identity --email-identity private@example.net"] = {"VerifiedForSendingStatus": True}
        text, code = report(answers)
        self.assertEqual(code, 0, text)
        self.assertIn("Replies to correspondents need production access", text)
        self.assertIn("has not been tried", text)

    def test_no_rule_set_at_all_gets_the_create_commands(self):
        for active in ({}, {"Metadata": None}, None):
            answers = dict(READY, **{LISTED: {"RuleSets": []}})
            if active is None:
                del answers[ACTIVE]
            else:
                answers[ACTIVE] = active
            text, code = report(answers)
            self.assertEqual(code, 1)
            self.assertIn("create-receipt-rule-set --rule-set-name relay", text)
            self.assertIn("set-active-receipt-rule-set --rule-set-name relay", text)
            self.assertNotIn("aws cloudformation deploy", text)

    def test_a_failed_read_never_suggests_activating_a_rule_set(self):
        unreadable = {k: v for k, v in READY.items() if k != ACTIVE}
        for answers in (unreadable, dict(unreadable, **{LISTED: {"RuleSets": [{"Name": "live"}]}}),
                        dict(unreadable, **{LISTED: {"RuleSets": ["junk"]}}), dict(unreadable, **{LISTED: {"RuleSets": 5}}),
                        dict(READY, **{ACTIVE: {}, LISTED: {"RuleSets": [], "NextToken": "more"}}),
                        dict(READY, **{ACTIVE: {}, LISTED: {}})):
            text, code = report(answers)
            self.assertEqual(code, 1)
            self.assertIn("Could not read the active receipt rule set", text)
            self.assertNotIn("set-active-receipt-rule-set", text)
            self.assertNotIn("aws cloudformation deploy", text)
        inactive = dict(READY, **{ACTIVE: {}, LISTED: {"RuleSets": [{"Name": "old"}]}})
        text, code = report(inactive)
        self.assertEqual(code, 1)
        self.assertIn("Rule sets exist here (old) but none is active", text)
        self.assertNotIn("create-receipt-rule-set", text)

    def test_rule_position(self):
        self.assertIn("AfterRule= OutboundEnabled=false", report(with_rules())[0])
        own = {"Name": "relay-inbound", "Recipients": [ALIAS]}
        first, later = {"Name": "first", "Recipients": ["a.example"]}, {"Name": "later", "Recipients": ["b.example"]}
        deployed = {STACK: {"Stacks": [{"StackStatus": "UPDATE_COMPLETE"}]}}
        for rules, expected in (((first, own), "first"), ((first, own, later), "first"), ((own, later), ""), ((own,), "")):
            text, code = report(dict(with_rules(*rules), **deployed))
            self.assertEqual(code, 0, text)
            self.assertIn(f"AfterRule={expected} ", text.replace("AfterRule=\n", "AfterRule= \n") + " ")

    def test_clashing_rules(self):
        for recipients in (["example.com"], [".com"], ["you@example.com"], ["reply@example.com"], ["EXAMPLE.COM"], [], None):
            text, code = report(with_rules({"Name": "catch", "Recipients": recipients}))
            self.assertEqual(code, 1, recipients)
            self.assertIn("The rule catch already receives mail", text)
        self.assertEqual(report(with_rules({"Name": "off", "Enabled": False, "Recipients": []}))[1], 0)
        for recipients in (["other.example"], [".example.org"], ["someone@example.com"], ["sub.example.com"]):
            self.assertEqual(report(with_rules({"Name": "fine", "Recipients": recipients}))[1], 0, recipients)

    def test_the_relays_rule_without_its_stack_is_not_deployed_over(self):
        text, code = report(with_rules({"Name": "relay-inbound", "Recipients": [ALIAS]}))
        self.assertEqual(code, 1)
        self.assertIn("no stack named mailrelay was found", text)
        self.assertNotIn("aws cloudformation deploy", text)

    def test_identity_states(self):
        answers = {k: v for k, v in READY.items() if k != IDENTITY}
        text, code = report(answers)
        self.assertEqual(code, 1)
        self.assertIn("example.com has no SES identity", text)
        self.assertIn("create-email-identity --email-identity example.com", text)
        for error in (DENIED, LOOKALIKE):
            text, code = report(answers, errors={IDENTITY: error})
            self.assertEqual(code, 1)
            self.assertIn("Could not read the SES identity", text)
            self.assertNotIn("create-email-identity", text)
        answers[IDENTITY] = {"IdentityType": "DOMAIN", "VerifiedForSendingStatus": False}
        self.assertIn("is not verified in SES yet", report(answers)[0])
        answers[IDENTITY] = {"IdentityType": "EMAIL_ADDRESS", "VerifiedForSendingStatus": True}
        text = report(answers)[0]
        self.assertIn("must be a domain identity", text)
        self.assertIn("create-email-identity --email-identity example.com", text)

    def test_existing_stack_keeps_its_settings(self):
        for status in check.HEALTHY:
            text, code = report(dict(READY, **{STACK: {"Stacks": [{"StackStatus": status}]}}))
            self.assertEqual(code, 0, text)
            self.assertIn("Ready. Update the stack:", text)
            self.assertNotIn("OutboundEnabled", text)
        text, code = report(dict(READY, **{STACK: {"Stacks": [{"StackStatus": "ROLLBACK_COMPLETE"}]}}))
        self.assertEqual(code, 1)
        self.assertIn("delete-stack --stack-name mailrelay", text)
        for status in ("ROLLBACK_FAILED", "DELETE_FAILED", "REVIEW_IN_PROGRESS", "UPDATE_IN_PROGRESS"):
            text, code = report(dict(READY, **{STACK: {"Stacks": [{"StackStatus": status}]}}))
            self.assertEqual(code, 1, status)
            self.assertIn(f"is in state {status}", text)
            self.assertNotIn("aws cloudformation deploy", text)

    def test_a_stack_that_cannot_be_read_is_not_taken_for_a_missing_one(self):
        for error in (DENIED, LOOKALIKE, "An error occurred (ValidationError) when calling the DescribeStacks "
                      "operation: Stack with id other does not exist", "An error occurred (Throttling) when calling the DescribeStacks operation: Rate exceeded", ""):
            text, code = report(READY, errors={STACK: error})
            self.assertEqual(code, 1, error)
            self.assertIn("Could not read the stack mailrelay", text)
            self.assertNotIn("aws cloudformation deploy", text)
            self.assertNotIn("OutboundEnabled", text)

    def test_lambda_concurrency(self):
        for free, code in ((1000, 0), (102, 0), (101, 1), (10, 1)):
            answers = dict(READY, **{LIMITS: {"AccountLimit": {"UnreservedConcurrentExecutions": free}}})
            text, got = report(answers)
            self.assertEqual(got, code, free)
            self.assertEqual("Concurrent executions" in text, bool(code), free)
        for answers in ({k: v for k, v in READY.items() if k != LIMITS}, dict(READY, **{LIMITS: {}})):
            self.assertEqual(report(answers)[1], 0)  # an unreadable limit is not a verdict
        held = {LIMITS: {"AccountLimit": {"UnreservedConcurrentExecutions": 100}},
                STACK: {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}}
        text, code = report(dict(READY, **held))  # an existing stack already holds its reservation
        self.assertEqual(code, 0, text)
        self.assertIn("Ready. Update the stack:", text)

    def test_leftovers_block_a_new_stack(self):
        leftovers = dict(READY, **{
            BUCKET: "", TABLE: {"Table": {}}, LOGS: {"logGroups": [{"logGroupName": "/aws/lambda/mailrelay"}]},
        })
        text, code = report(leftovers)
        self.assertEqual(code, 1)
        for part in ("bucket mailrelay-123456789012-us-east-1", "table mailrelay", "log group /aws/lambda/mailrelay",
                     "holds your reply addresses"):
            self.assertIn(part, text)
        other = dict(READY, **{LOGS: {"logGroups": [{"logGroupName": "/aws/lambda/mailrelay-other"}]}})
        self.assertEqual(report(other)[1], 0)
        text, code = report(dict(READY, **{LOGS: leftovers[LOGS]}))
        self.assertEqual(code, 1)
        self.assertIn("log group /aws/lambda/mailrelay", text)
        self.assertNotIn("holds your reply addresses", text)
        for errors in ({BUCKET: "An error occurred (403) when calling the HeadBucket operation: Forbidden"},
                       {TABLE: DENIED}, {LOGS: DENIED}, {TABLE: LOOKALIKE}, {BUCKET: LOOKALIKE}):
            text, code = report(READY, errors=errors)
            self.assertEqual(code, 1, errors)
            self.assertIn("Could not check for leftovers", text)
            self.assertNotIn("aws cloudformation deploy", text)

    def test_dns_checks(self):
        elsewhere = dict(READY, **{MX: "1 aspmx.l.google.com.\n5 alt1.aspmx.l.google.com.\n"})
        text, code = report(elsewhere)
        self.assertEqual(code, 1)
        self.assertIn("already receives mail at aspmx.l.google.com", text)
        self.assertIn("r.example.com", text)
        text, code = report(dict(READY, **{MX: ""}))
        self.assertEqual(code, 0, text)
        self.assertIn("has no MX record yet. Add it after the stack exists", text)
        self.assertIn("Ready. Deploy with replies off:", text)
        retried = ";; communications error to 10.0.0.1#53: timed out\n" + READY[MX]
        self.assertIn("delivers its mail to SES", report(dict(READY, **{MX: retried}))[0])
        text, code = report(dict(READY, **{MX: "0 .\n"}))
        self.assertEqual(code, 0, text)
        self.assertIn("has no MX record yet", text)
        text, code = report({k: v for k, v in READY.items() if k != MX})
        self.assertEqual(code, 0, text)
        self.assertIn("dig did not answer", text)
        text, code = report(dict(READY, **{DMARC: ""}))
        self.assertEqual(code, 1)
        self.assertIn("publishes no DMARC record", text)
        text, code = report({k: v for k, v in READY.items() if k != DMARC})  # the lookup failed
        self.assertEqual(code, 0, text)
        self.assertIn("dig did not answer for _dmarc.example.net", text)
        self.assertNotIn("publishes no DMARC record", text)
        text, code = report(READY, has_dig=False)
        self.assertEqual(code, 0, text)
        self.assertIn("dig is not installed", text)
        self.assertNotIn("dig +short", text)

    def test_dmarc_on_a_parent_domain(self):
        base = {k: v for k, v in READY.items() if k != DMARC}
        for inbox, record_at in (("me@mail.example.net", "example.net"), ("me@mail.example.co.uk", "example.co.uk"),
                                 ("me@a.b.example.net", "b.example.net")):
            answers = dict(base, **{f"dig +short TXT _dmarc.{record_at}": '"v=DMARC1; p=reject"\n'})
            text, code = check.Check(REGION, DOMAIN, ALIAS, inbox, run=runner(answers), has_dig=True).report()
            self.assertEqual(code, 0, text)
            self.assertIn(f"has no DMARC record of its own; {record_at} publishes one", text)
            self.assertNotIn("ok   " + inbox.split("@")[1] + " publishes", text)

    def test_bad_arguments_and_an_unreachable_account(self):
        for alias, inbox in (("You@example.com", INBOX), ("you@other.example", INBOX), (ALIAS, "me@Example.NET"),
                             (ALIAS, "me@example.com"), (ALIAS, "not-an-address")):
            text, code = report(READY, alias=alias, inbox=inbox)
            self.assertEqual(code, 1, (alias, inbox))
        for answers in ({}, {"sts get-caller-identity": {}}, {"sts get-caller-identity": ""},
                        {"sts get-caller-identity": "not json"}, {"sts get-caller-identity": []}):
            text, code = report(answers)
            self.assertEqual(code, 1, answers)
            self.assertIn("cannot reach your account", text)
        self.assertEqual(check.run_command(["no-such-command-for-this-test"]), (127, "", "not installed"))

    def test_unexpected_shapes_never_raise(self):
        shapes = (
            {ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": None}},
            {ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": [{"Recipients": ["x.example"]}, "junk", None]}},
            {ACTIVE: []}, {ACTIVE: "not json"}, {STACK: {"Stacks": None}}, {STACK: {"Stacks": ["junk"]}},
            {"sesv2 get-account": []}, {IDENTITY: []}, {LISTED: {"RuleSets": ["junk"]}},
            {"logs describe-log-groups --log-group-name-prefix /aws/lambda/mailrelay": {"logGroups": ["junk", None]}},
            {MX: "garbage\n\n"}, {DMARC: "\n"}, {MX: '""\n " "\n'}, {ACTIVE: "[" * 100000}, {STACK: '{"a":' * 100000},
            {ACTIVE: {"Metadata": "main-rules"}}, {ACTIVE: {"Metadata": 5}, LISTED: {"RuleSets": 5}},
            {ACTIVE: {}, LISTED: {"RuleSets": True}}, {ACTIVE: {}, LISTED: {"RuleSets": [], "NextToken": "more"}},
            {ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": 5}},
            {ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": True}},
            {ACTIVE: {"Metadata": {"Name": "main-rules"}, "Rules": [{"Name": "odd", "Recipients": 5}, {"Name": 7}]}},
            {STACK: {"Stacks": 5}}, {STACK: {"Stacks": [{"StackStatus": None}]}}, {LOGS: {"logGroups": True}},
            {LIMITS: {"AccountLimit": 5}}, {LIMITS: {"AccountLimit": {"UnreservedConcurrentExecutions": "many"}}},
        )
        for shape in shapes:
            text, code = report(dict(READY, **shape))
            self.assertIn(code, (0, 1), shape)
            self.assertIn("Not checked here", text)

    def test_values_are_quoted_for_the_shell(self):
        text, code = report(READY, inbox="o'brien@example.net")
        self.assertEqual(code, 0, text)
        self.assertIn(shlex.quote("PrivateAddress=o'brien@example.net"), text)
        self.assertNotIn(" PrivateAddress=o'brien@example.net ", text)
        text, code = report(READY, inbox="first.last+tag@example.net")
        self.assertEqual(code, 0, text)
        self.assertIn("PrivateAddress=first.last+tag@example.net", text)


if __name__ == "__main__":
    unittest.main()
