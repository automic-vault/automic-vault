import pathlib
import subprocess
import tempfile
import unittest


class InstallerTests(unittest.TestCase):
    def test_cli_install_only_requests_sudo_when_binary_differs(self):
        script = (pathlib.Path(__file__).resolve().parents[1] / "scripts/dist/install.sh").read_text()
        cli_install = script.split('/usr/bin/ditto "$app" "/Applications/Automic Vault.app"\n', 1)[1]
        for existing in (None, b"old binary", b"new binary"):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                source = root / "Contents/MacOS/av"
                source.parent.mkdir(parents=True)
                source.write_bytes(b"new binary")
                destination = root / "bin/av"
                if existing is not None:
                    destination.parent.mkdir()
                    destination.write_bytes(existing)
                commands = cli_install.replace("/usr/local/bin", '"$app/bin"').replace("/usr/bin/sudo", "sudo")
                result = subprocess.run(
                    ["/bin/sh", "-ec", 'app=$1; sudo() { echo sudo; "$@"; };\n' + commands, "test", tmp],
                    capture_output=True, text=True, check=True,
                )
                self.assertEqual(result.stdout.count("sudo\n"), 0 if existing == b"new binary" else 2)
                self.assertEqual(destination.read_bytes(), b"new binary")


if __name__ == "__main__":
    unittest.main()
