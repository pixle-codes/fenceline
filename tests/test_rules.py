import os
import tempfile
import unittest

from fenceline.model import Event
from fenceline.rules import (
    audit,
    check_listen,
    check_outside_root,
    check_remote_host,
    default_policy,
)


def ev(command="", tool="bash", target="", ts=1700000000.0, sid="s1"):
    return Event(ts=ts, sid=sid, tool=tool, target=target, command=command)


class TestForbiddenHead(unittest.TestCase):
    def setUp(self):
        self.pol = default_policy()

    def test_sudo_flagged(self):
        fs = audit([ev("sudo apt update")], self.pol)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].rule, "forbidden-command")
        self.assertEqual(fs[0].severity, "error")

    def test_absolute_path_head_flagged(self):
        fs = audit([ev("/usr/bin/sudo reboot")], self.pol)
        self.assertTrue(any(f.rule == "forbidden-command" for f in fs))

    def test_prose_mention_clean(self):
        self.assertEqual(audit([ev("echo sudo is a forbidden word")], self.pol), [])
        self.assertEqual(audit([ev("grep systemctl file.txt")], self.pol), [])

    def test_docker_and_apt(self):
        self.assertTrue(audit([ev("docker ps")], self.pol))
        self.assertTrue(audit([ev("apt-get install -y curl")], self.pol))


class TestDestructivePatterns(unittest.TestCase):
    def setUp(self):
        self.pol = default_policy()

    def test_mkfs_anywhere(self):
        fs = audit([ev("/sbin/mkfs.ext4 /dev/sda1")], self.pol)
        self.assertEqual(fs[0].rule, "destructive-pattern")

    def test_rm_rf_root_only(self):
        self.assertEqual(len(audit([ev("rm -rf /")], self.pol)), 1)
        self.assertEqual(len(audit([ev("rm -fr / ")], self.pol)), 1)
        self.assertEqual(audit([ev("rm -rf /tmp/build")], self.pol), [])
        self.assertEqual(audit([ev("rm -rf ./node_modules")], self.pol), [])
        self.assertEqual(
            audit([ev("rm -rf /home/builder/projects/x")], self.pol), []
        )

    def test_chmod_777_root_only(self):
        self.assertTrue(audit([ev("chmod -R 777 /")], self.pol))
        self.assertEqual(audit([ev("chmod 777 ./script.sh")], self.pol), [])

    def test_dd_raw_device(self):
        self.assertTrue(audit([ev("dd if=img.iso of=/dev/sda")], self.pol))


class TestOutsideRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        home = os.path.join(self.tmp.name, "home")
        os.makedirs(os.path.join(home, "proj"))
        self.pol = default_policy()
        self.pol.allowed_roots = [home]
        self.home = home

    def tearDown(self):
        self.tmp.cleanup()

    def test_inside_ok(self):
        t = os.path.join(self.home, "proj", "a.py")
        self.assertIsNone(check_outside_root(ev(tool="write", target=t), self.pol))

    def test_outside_flagged(self):
        f = check_outside_root(ev(tool="edit", target="/etc/passwd"), self.pol)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "outside-root")
        self.assertIn("->", f.evidence)

    def test_symlink_escape_flagged(self):
        link = os.path.join(self.home, "sneaky")
        os.symlink("/etc/passwd", link)
        f = check_outside_root(ev(tool="write", target=link), self.pol)
        self.assertIsNotNone(f)

    def test_urls_ignored(self):
        self.assertIsNone(
            check_outside_root(
                ev(tool="fetch", target="https://example.com"), self.pol
            )
        )

    def test_bash_never_path_checked(self):
        self.assertIsNone(
            check_outside_root(ev(command="cat /etc/passwd"), self.pol)
        )


class TestRemoteHost(unittest.TestCase):
    def setUp(self):
        self.pol = default_policy()
        self.pol.remote_host = "storagebox"
        self.pol.remote_allow = "agent-backup"

    def test_inactive_without_host_config(self):
        pol = default_policy()
        self.assertIsNone(check_remote_host(ev("ssh storagebox ls"), pol))

    def test_violation(self):
        f = check_remote_host(ev('ssh storagebox "ls ~owner"'), self.pol)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "remote-host")

    def test_allowed_subdir_clean(self):
        self.assertIsNone(
            check_remote_host(ev("rsync -az out/ storagebox:agent-backup/out/"), self.pol)
        )

    def test_other_hosts_ignored(self):
        self.assertIsNone(check_remote_host(ev("ssh otherhost ls"), self.pol))


class TestListen(unittest.TestCase):
    def setUp(self):
        self.pol = default_policy()

    def test_http_server_warn(self):
        f = check_listen(ev("python3 -m http.server 8000"), self.pol)
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "warn")
        self.assertEqual(f.rule, "listen-server")

    def test_curl_clean(self):
        self.assertIsNone(check_listen(ev("curl https://api.example.com"), self.pol))

    def test_nc_listen(self):
        self.assertIsNotNone(check_listen(ev("nc -l 9999"), self.pol))

    def test_npm_dev_vs_build(self):
        self.assertIsNotNone(check_listen(ev("npm run dev"), self.pol))
        self.assertIsNone(check_listen(ev("npm run build"), self.pol))


class TestAudit(unittest.TestCase):
    def test_sorted_and_multi_rule(self):
        pol = default_policy()
        events = [
            ev("python3 -m http.server", ts=100.0),
            ev("sudo ls", ts=50.0),
            ev(tool="write", target="/etc/cron.d/x", ts=75.0),
        ]
        fs = audit(events, pol)
        rules = [f.ts for f in fs]
        self.assertEqual(rules, sorted(rules))
        self.assertEqual({f.rule for f in fs}, {
            "forbidden-command", "outside-root", "listen-server",
        })


if __name__ == "__main__":
    unittest.main()
