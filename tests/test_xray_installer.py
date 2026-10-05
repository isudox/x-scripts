"""Offline checks: no root, network or system mutations required."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

SCRIPT = Path(__file__).resolve().parents[1] / "cmd/xray/install-vless.sh"


def shell(code, *args, stdin=None):
    return subprocess.run(
        ["bash", "-c", 'source "$1"; shift; ' + code, "test", str(SCRIPT), *args],
        input=stdin, text=True, capture_output=True,
    )


class InstallerTests(unittest.TestCase):
    def test_connection_info_file_contents_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'connection-info.txt'
            destination.write_text('old credentials')
            destination.chmod(0o644)
            result = shell('''
              ADDRESS=203.0.113.10; PORT=8443; SNI=www.example.com
              UUID=test-uuid; PUBLIC_KEY=test-public; PRIVATE_KEY=test-private
              SHORT_ID=0123456789abcdef
              save_connection_info "$1" 'vless://test-link'
            ''', str(destination))
            self.assertEqual(result.returncode, 0, result.stderr)
            content = destination.read_text()
            for field in ['Address: 203.0.113.10', 'Port: 8443', 'UUID: test-uuid',
                          'PublicKey (Password): test-public', 'PrivateKey: test-private',
                          'SNI: www.example.com', 'Target: www.example.com:443',
                          'shortId: 0123456789abcdef', 'vless://test-link']:
                self.assertIn(field, content)
            self.assertNotIn('old credentials', content)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).glob('*.tmp.*')), [])
            self.assertNotIn('test-private', result.stdout + result.stderr)

    def test_debian_family_without_version_restriction(self):
        for distro, like, version in [
            ('ubuntu', '', '24.04'), ('ubuntu', 'debian', '26.04'),
            ('debian', '', '13'), ('debian', '', '13.6'),
            ('linuxmint', 'ubuntu debian', '22'), ('pop', 'ubuntu', '24.04'),
            ('derivative', 'other debian', ''),
        ]:
            with self.subTest(distro=distro, version=version):
                result = shell('ID=$1; ID_LIKE=$2; VERSION_ID=$3; is_debian_family',
                               distro, like, version)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unrelated_or_missing_distro_is_rejected(self):
        for distro, like in [('fedora', 'rhel'), ('alpine', ''),
                             ('notdebian', 'notubuntu'), ('', '')]:
            with self.subTest(distro=distro):
                result = shell('ID=$1; ID_LIKE=$2; is_debian_family', distro, like)
                self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(shell('unset ID ID_LIKE VERSION_ID; is_debian_family').returncode, 0)

    def test_share_uri_matches_config_and_encodes_name(self):
        result = shell('''
          parse_args "$@"
          UUID=12345678-1234-4321-8123-123456789abc
          PRIVATE_KEY=server-secret
          PUBLIC_KEY=abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE
          SHORT_ID=0123456789abcdef
          write_config
          printf '\\n'
          generate_vless_uri
        ''', '--address', '203.0.113.10', '--port', '8443', '--sni', 'www.example.com',
                       '--name', '香港 节点 & # / + %')
        self.assertEqual(result.returncode, 0, result.stderr)
        config_text, uri = result.stdout.rstrip().rsplit('\n', 1)
        inbound = json.loads(config_text)['inbounds'][0]
        reality = inbound['streamSettings']['realitySettings']
        parsed = urlsplit(uri)
        self.assertEqual(parsed.scheme, 'vless')
        self.assertEqual(parsed.hostname, '203.0.113.10')
        self.assertEqual(parsed.port, inbound['port'])
        self.assertEqual(parsed.username, inbound['settings']['clients'][0]['id'])
        self.assertEqual(unquote(parsed.fragment), '香港 节点 & # / + %')
        self.assertTrue(uri.isascii())
        self.assertNotIn(' ', uri)
        self.assertNotIn('server-secret', uri)
        self.assertEqual(parse_qs(parsed.query), {
            'encryption': ['none'], 'type': ['tcp'], 'headerType': ['none'],
            'security': ['reality'], 'flow': [inbound['settings']['clients'][0]['flow']],
            'sni': reality['serverNames'], 'fp': ['chrome'],
            'pbk': ['abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE'],
            'sid': reality['shortIds'],
        })

    def test_random_sni_retries_and_config_uses_selection(self):
        result = shell('''
          shuffle_sni_candidates() { printf 'bad.example.com\\ngood.example.com\\n'; }
          probe_sni() { [[ $1 == good.example.com ]]; }
          select_sni >&2
          UUID=test-id; PRIVATE_KEY=secret; SHORT_ID=0123456789abcdef
          write_config
        ''', stdin='')
        self.assertEqual(result.returncode, 0, result.stderr)
        reality = json.loads(result.stdout)['inbounds'][0]['streamSettings']['realitySettings']
        self.assertEqual(reality['target'], 'good.example.com:443')
        self.assertEqual(reality['serverNames'], ['good.example.com'])
        self.assertIn('尝试下一个', result.stderr)

    def test_all_sni_candidates_fail(self):
        result = shell('probe_sni() { return 1; }; select_sni', stdin='')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('所有 SNI 候选均不可用', result.stderr)

    def test_explicit_sni_no_fallback(self):
        for success in (True, False):
            result = shell('parse_args "$@"; '
                           'shuffle_sni_candidates() { echo UNEXPECTED; }; '
                           f'probe_sni() {{ return {0 if success else 1}; }}; '
                           'select_sni; printf "%s" "$SNI"',
                           '--address', '203.0.113.10', '--sni', 'www.example.com', stdin='')
            self.assertEqual(result.returncode == 0, success)
            self.assertNotIn('UNEXPECTED', result.stdout)
            self.assertIn('www.example.com', result.stdout + result.stderr)

    def test_shuffle_preserves_candidate_pool(self):
        result = shell('printf "%s\\n" "${SNI_CANDIDATES[@]}"; printf "%s\\n" "---split---"; shuffle_sni_candidates')
        # Avoid probabilistic ordering assertions; verify every candidate occurs once.
        self.assertEqual(result.returncode, 0, result.stderr)
        original, shuffled = result.stdout.split('---split---\n')
        self.assertCountEqual(original.splitlines(), shuffled.splitlines())
        self.assertEqual(len(set(shuffled.splitlines())), len(shuffled.splitlines()))

    def test_options(self):
        result = shell('parse_args "$@"; printf "%s %s %s" "$PORT" "$FORCE" "$UPGRADE"',
                       "--address", "203.0.113.10", "--port", "08443", "--force", "--skip-upgrade")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "8443 1 0")

    def test_invalid_options(self):
        for args in [[], ["--address"], ["--unknown"],
                     ["--address", "999.1.1.1"], ["--address", "a..com"],
                     ["--address", "https://example.com"],
                     ["--address", "example.com", "--port", "0"],
                     ["--address", "example.com", "--port", "65536"],
                     ["--address", "example.com", "--sni", "1.1.1.1"],
                     ["--address", "example.com", "--sni", 'x.com"; echo injected']]:
            with self.subTest(args=args):
                self.assertNotEqual(shell('parse_args "$@"', *args).returncode, 0)

    def test_key_formats(self):
        for private, public in [("PrivateKey", "Password"), ("Private key", "Public key"),
                                ("PrivateKey", "PublicKey"),
                                ("PrivateKey", "Password (PublicKey)")]:
            output = f"{private}: secret\n{public}: client\nHash32: ignored\n"
            self.assertEqual(shell("key_field private", stdin=output).stdout.strip(), "secret")
            self.assertEqual(shell("key_field public", stdin=output).stdout.strip(), "client")

    def test_current_xray_keys_pass_validation(self):
        private_key = 'A' * 43
        public_key = 'B' * 43
        output = f'PrivateKey: {private_key}\r\nPassword (PublicKey): {public_key}\r\nHash32: ignored\r\n'
        result = shell('''
          keys=$(cat)
          PRIVATE_KEY=$(key_field private <<< "$keys")
          PUBLIC_KEY=$(key_field public <<< "$keys")
          [[ $PRIVATE_KEY =~ ^[A-Za-z0-9_-]{43}$ && $PUBLIC_KEY =~ ^[A-Za-z0-9_-]{43}$ ]]
          printf '%s\\n%s\\n' "$PRIVATE_KEY" "$PUBLIC_KEY"
        ''', stdin=output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [private_key, public_key])

    def test_configuration(self):
        result = shell('SNI=www.microsoft.com; UUID=test-id; PRIVATE_KEY=secret; SHORT_ID=0123456789abcdef; write_config')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["port"], 443)
        self.assertEqual(inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        reality = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["target"], "www.microsoft.com:443")
        self.assertEqual(reality["privateKey"], "secret")
        self.assertEqual(len(reality["shortIds"][0]), 16)

    def test_failure_restores_config(self):
        # Exercise the EXIT trap with fake systemctl, confined to a temporary folder.
        result = shell('''
          WORK=$(mktemp -d)
          CONFIG="$WORK/config.json"; BACKUP="$WORK/backup"
          printf old > "$BACKUP"; printf new > "$CONFIG"
          REPLACED=1; WAS_ACTIVE=1
          systemctl() { printf 'systemctl %s\\n' "$*"; }
          cp() { command cp "$@"; printf 'restored: '; cat "$CONFIG"; }
          trap cleanup EXIT
          exit 7
        ''')
        self.assertEqual(result.returncode, 7)
        self.assertIn("restored: old", result.stdout)
        self.assertIn("systemctl restart xray", result.stdout)


if __name__ == "__main__":
    unittest.main()
