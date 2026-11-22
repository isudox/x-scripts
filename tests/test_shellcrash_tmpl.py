import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "rule_tmpl" / "ShellCrash.ini"
QX_CONF = ROOT / "quantumult" / "quantumultx.conf"

BUILTINS = {"DIRECT", "REJECT"}
# sing-box 不支持或已移除的规则类型
UNSUPPORTED_INLINE = ("GEOIP", "IP-ASN", "USER-AGENT", "URL-REGEX", "GEOSITE")


def load_template():
    rulesets, groups = [], {}
    for raw in TEMPLATE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        if key == "ruleset":
            target, _, source = value.partition(",")
            rulesets.append((target, source))
        elif key == "custom_proxy_group":
            fields = value.split("`")
            groups[fields[0]] = fields[1:]
    return rulesets, groups


class ShellCrashTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rulesets, cls.groups = load_template()

    def test_ruleset_targets_are_defined(self):
        for target, source in self.rulesets:
            with self.subTest(source=source):
                self.assertTrue(target in self.groups or target in BUILTINS, target)

    def test_select_members_are_defined(self):
        for name, fields in self.groups.items():
            group_type, members = fields[0], fields[1:]
            self.assertIn(group_type, {"select", "url-test"}, name)
            if group_type != "select":
                continue
            for member in members:
                if not member.startswith("[]"):
                    continue
                ref = member[2:]
                with self.subTest(group=name, member=ref):
                    self.assertNotEqual(ref, name)
                    self.assertTrue(ref in self.groups or ref in BUILTINS, ref)

    def test_url_test_groups_are_well_formed(self):
        for name, fields in self.groups.items():
            if fields[0] != "url-test":
                continue
            with self.subTest(group=name):
                self.assertEqual(len(fields), 4)
                re.compile(fields[1])
                self.assertTrue(fields[2].startswith("http"))
                self.assertRegex(fields[3], r"^\d+,\d*,\d+$")

    def test_final_rule_is_last_and_unique(self):
        finals = [r for r in self.rulesets if r[1] == "[]FINAL"]
        self.assertEqual(len(finals), 1)
        self.assertEqual(self.rulesets[-1], ("兜底分流", "[]FINAL"))

    def test_no_singbox_unsupported_inline_rules(self):
        for _, source in self.rulesets:
            if source.startswith("[]"):
                rule_type = source[2:].split(",", 1)[0]
                self.assertNotIn(rule_type, UNSUPPORTED_INLINE, source)

    def test_groups_match_quantumultx_policies(self):
        qx = QX_CONF.read_text(encoding="utf-8")
        policy = qx.split("[policy]", 1)[1].split("\n[", 1)[0]
        names = re.findall(
            r"^(?:static|url-latency-benchmark)\s*=\s*([^,]+),", policy, re.M
        )
        self.assertTrue(names)
        for name in names:
            with self.subTest(policy=name.strip()):
                self.assertIn(name.strip(), self.groups)

        benchmarks = re.findall(
            r"^url-latency-benchmark\s*=\s*([^,]+),", policy, re.M
        )
        for name in benchmarks:
            self.assertEqual(self.groups[name.strip()][0], "url-test")


if __name__ == "__main__":
    unittest.main()
