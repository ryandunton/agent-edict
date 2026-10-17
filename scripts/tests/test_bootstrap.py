"""Isolated bootstrap regression tests. Network, git, and openssl are mocked."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANAGEMENT = "fake-management-token-for-test"
ENDPOINT = "fake-endpoint-token-for-test"

MOCK = r'''#!{python}
import json, os, pathlib, sys
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(json.dumps([command, args]) + '\n')
if command == 'git':
    sys.exit(0)
if command == 'openssl':
    if os.environ.get('MOCK_CASE') == 'openssl-failure': sys.exit(7)
    output = args[args.index('-out') + 1]
    pathlib.Path(output).write_text('-----BEGIN PUBLIC KEY-----\nPUBLIC_TEST_DATA\n-----END PUBLIC KEY-----\n')
    sys.exit(0)
if command != 'curl': sys.exit(95)
url = args[-1]
method = args[args.index('--request') + 1]
status, data = 200, {{'id': 12345}}
case = os.environ.get('MOCK_CASE', '')
if url.endswith('/user'):
    data = {{'username': 'test-user'}}
elif url.endswith('/variables/EDICT_SIGNING_PRIVATE_KEY'):
    status, data = 404, {{'message': 'not found'}}
elif url.endswith('/variables'):
    status, data = 201, {{'key': 'EDICT_SIGNING_PRIVATE_KEY'}}
elif url.endswith('/deploy_tokens'):
    assert url.endswith('/projects/12345/deploy_tokens'), url
    status, data = 201, {{'token': '{endpoint}', 'scopes': ['read_package_registry']}}
    if case == 'deploy-http-failure': status = 403
    if case == 'deploy-broad-scope': data['scopes'].append('write_repository')
    if case == 'deploy-missing-token': del data['token']
    if case == 'deploy-invalid-json': data = None
elif '/pipeline?' in url:
    status, data = 201, {{'id': 876}}
pathlib.Path(args[args.index('--output') + 1]).write_text(json.dumps(data) if data is not None else '<invalid>')
print(status, end='')
'''


class BootstrapTests(unittest.TestCase):
    def run_setup(self, case="", with_token=True):
        temp = tempfile.TemporaryDirectory(prefix="edict-bootstrap-test-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "scripts").mkdir()
        (root / "cmd/edict").mkdir(parents=True)
        (root / "fakebin").mkdir()
        shutil.copyfile(ROOT / "scripts/setup-gitlab.sh", root / "scripts/setup-gitlab.sh")
        (root / "cmd/edict/main.go").write_text('package main\nconst defaultPublicKeyPEM = `OLD`\n')
        for command in ("curl", "git", "openssl"):
            path = root / "fakebin" / command
            path.write_text(MOCK.format(python=shutil.which("python3"), endpoint=ENDPOINT))
            path.chmod(0o700)
        env = os.environ.copy()
        env.update(PATH=str(root / "fakebin") + os.pathsep + env["PATH"], MOCK_LOG=str(root / "calls.jsonl"), MOCK_CASE=case)
        env.pop("GITLAB_TOKEN", None)
        env.pop("GITLAB_NAMESPACE", None)
        if with_token:
            env["GITLAB_TOKEN"] = MANAGEMENT
        result = subprocess.run(["bash", str(root / "scripts/setup-gitlab.sh")], env=env, text=True, capture_output=True, stdin=subprocess.DEVNULL)
        # No credential, even a fake one, may escape to output or native argv.
        trace = (root / "calls.jsonl").read_text() if (root / "calls.jsonl").exists() else ""
        for secret in (MANAGEMENT, ENDPOINT):
            self.assertNotIn(secret, result.stdout + result.stderr + trace)
        return root, result, trace

    def test_valid_deploy_token_is_private_and_never_logged(self):
        root, result, trace = self.run_setup()
        self.assertEqual(0, result.returncode, result.stderr)
        files = list((root / "keys").glob("agent-edict-deploy-token-*"))
        self.assertEqual(1, len(files))
        self.assertEqual(ENDPOINT + "\n", files[0].read_text())
        self.assertEqual(0o600, stat.S_IMODE(files[0].stat().st_mode))
        self.assertIn("-deploy-token-file", result.stdout)
        self.assertIn("projects/12345/deploy_tokens", trace)
        self.assertNotIn("oauth2:", trace)
        self.assertIn('= `-----BEGIN PUBLIC KEY-----\nPUBLIC_TEST_DATA\n-----END PUBLIC KEY-----`', (root / "cmd/edict/main.go").read_text())

    def test_rejects_failed_or_overscoped_creation_without_fallback(self):
        for case in ("deploy-http-failure", "deploy-broad-scope", "deploy-missing-token", "deploy-invalid-json"):
            with self.subTest(case=case):
                root, result, trace = self.run_setup(case)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], list((root / "keys").glob("agent-edict-deploy-token-*")))
                self.assertNotIn("pipeline?", trace)
                self.assertNotIn("Setup complete", result.stdout)

    def test_missing_management_token_fails_before_network(self):
        _, result, trace = self.run_setup(with_token=False)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", trace)

    def test_native_key_generation_failure_stops_before_push(self):
        _, result, trace = self.run_setup("openssl-failure")
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('"git"', trace)

    def test_install_rejects_raw_token_argument_without_printing_it(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/install-agent.sh"), "https://example.invalid/bundle", ENDPOINT], text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Raw deploy-token arguments are not supported", result.stderr)
        self.assertNotIn(ENDPOINT, result.stdout + result.stderr)

    def test_unix_executable_ancestor_validation(self):
        with tempfile.TemporaryDirectory(prefix="edict-install-path-") as temp:
            directory = Path(temp).resolve() / "ancestor" / "bin"
            directory.mkdir(parents=True)
            target = directory / "edict"
            target.write_text("test")
            env = os.environ.copy()
            env.update(INSTALLER=str(ROOT / "scripts/install-agent.sh"), CHECK_PATH=str(target), BAD_COMPONENT=str(directory.parent))
            # Only stat and Darwin ACL discovery are mocked. The real isolated
            # path walk and symlink checks still run, without touching a service.
            script = r"""
source "$INSTALLER"
OS=linux
stat() {
  if [[ "${@: -1}" == "$BAD_COMPONENT" ]]; then printf '%s\n' "$MOCK_METADATA"; else printf '0 755\n'; fi
}
assert_trusted_executable_path "$CHECK_PATH"
"""
            for metadata, succeeds in (("0 755", True), ("501 755", False), ("0 775", False), ("0 777", False)):
                with self.subTest(metadata=metadata):
                    env["MOCK_METADATA"] = metadata
                    result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
                    self.assertEqual(succeeds, result.returncode == 0, result.stderr)
            env["MOCK_METADATA"] = "0 755"
            target.unlink()
            target.symlink_to(directory / "missing")
            result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("symlink", result.stderr)
            target.unlink()
            target.write_text("test")
            darwin_script = script.replace("OS=linux", "OS=darwin\nls() { printf 'drwxr-xr-x  root wheel path\\n 0: user:other allow write\\n'; }")
            result = subprocess.run(["bash", "-c", darwin_script], env=env, text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("ACL requires administrator review", result.stderr)

    def test_install_parses_sync_interval(self):
        with tempfile.TemporaryDirectory(prefix="edict-install-args-") as temp:
            token = Path(temp) / "token"
            token.write_text("fake-token\n")
            script = 'source "$INSTALLER"\nparse_install_args "$@" && printf "%s|%s|%s\\n" "$BUNDLE_URL" "$TOKEN_SOURCE" "$SYNC_INTERVAL_MINUTES"\n'
            env = os.environ.copy()
            env["INSTALLER"] = str(ROOT / "scripts/install-agent.sh")
            run = lambda *args: subprocess.run(["bash", "-c", script, "bash", *args], env=env, text=True, capture_output=True)
            url = "https://example.invalid/bundle"
            for args, want in (
                ((url,), f"{url}||15"),
                ((url, "--sync-interval-minutes", "60"), f"{url}||60"),
                ((url, "--deploy-token-file", str(token), "--sync-interval-minutes", "1440"), f"{url}|{token}|1440"),
                ((url, "--sync-interval-minutes", "1", "--deploy-token-file", str(token)), f"{url}|{token}|1"),
            ):
                with self.subTest(args=args):
                    result = run(*args)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(want, result.stdout.strip())
            for bad in ("0", "1441", "015", "abc", "-5", "", "1.5"):
                with self.subTest(bad=bad):
                    result = run(url, "--sync-interval-minutes", bad)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("1 to 1440", result.stderr)
            result = run(url, "--sync-interval-minutes")
            self.assertNotEqual(0, result.returncode)
            result = run(url, "--unknown", ENDPOINT)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(ENDPOINT, result.stdout + result.stderr)

    def test_service_template_reads_sync_interval(self):
        unit = (ROOT / "deploy/systemd/agent-edict.service").read_text()
        self.assertIn("Environment=EDICT_SYNC_INTERVAL=15m", unit)
        self.assertIn('-interval "${EDICT_SYNC_INTERVAL}"', unit)
        self.assertLess(unit.index("Environment=EDICT_SYNC_INTERVAL"), unit.index("EnvironmentFile="))

    def test_service_template_uses_token_file(self):
        unit = (ROOT / "deploy/systemd/agent-edict.service").read_text()
        self.assertIn('-deploy-token-file "${EDICT_DEPLOY_TOKEN_FILE}"', unit)
        self.assertNotIn('${EDICT_DEPLOY_TOKEN}', unit)


if __name__ == "__main__":
    unittest.main()
