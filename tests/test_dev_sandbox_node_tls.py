"""Exercise sandbox CA wiring with real npm, TLS, and the fixture proxy.

Only bubblewrap is replaced: its emitted environment is applied to the real
installer's node-deps stage, so these tests need no privileged namespaces or
external registry access.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ASSETS = REPO_ROOT / "scripts" / "sandbox"
pytestmark = pytest.mark.linux_only


def _make_ca(directory: Path) -> None:
    directory.mkdir(parents=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN={directory.name}",
            "-config",
            str(ASSETS / "openssl.cnf"),
            "-extensions",
            "sandbox_ca_ext",
            "-keyout",
            str(directory / "ca.key"),
            "-out",
            str(directory / "ca.pem"),
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )


def _stage2_environment(tmp_path: Path, certs: Path) -> dict[str, str]:
    root = certs.parent.parent
    (root / "root" / "logs").mkdir()
    (root / "root" / "logs" / "slirp.ready").write_text("1", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    bwrap = bin_dir / "bwrap"
    bwrap.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "print(json.dumps({args[i+1]: args[i+2] for i, arg in enumerate(args) "
        "if arg == '--setenv'}))\n",
        encoding="utf-8",
    )
    bwrap.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ASSETS / "stage2-run.sh"), "true"],
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "DEV_SANDBOX_ROOT": str(root),
            "DEV_SANDBOX_BASH": shutil.which("bash"),
            "DEV_SANDBOX_INTERACTIVE": "false",
            "DEV_SANDBOX_USER": "hermes",
            "DEV_SANDBOX_HOME": str(tmp_path / "home"),
        },
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    environment = json.loads(result.stdout)
    # Translate the /work bind mount while retaining the actual emitted values.
    return {
        name: str(root / "root" / value.removeprefix("/work/"))
        if value.startswith("/work/")
        else value
        for name, value in environment.items()
    }


@pytest.fixture
def sandbox(tmp_path: Path):
    for command in ("node", "npm", "openssl"):
        if shutil.which(command) is None:
            pytest.skip(f"requires {command}")
    certs = tmp_path / "sandbox" / "root" / "certs"
    _make_ca(certs)
    upstream = tmp_path / "upstream"
    _make_ca(upstream)
    shutil.copyfile(upstream / "ca.pem", certs / "real-ca.pem")
    return certs, upstream, _stage2_environment(tmp_path, certs)


@pytest.mark.parametrize("issuer", ["sandbox", "upstream", "untrusted"])
def test_installer_npm_verifies_sandbox_and_upstream_cas(
    tmp_path: Path,
    monkeypatch,
    sandbox,
    issuer: str,
) -> None:
    certs, upstream, environment = sandbox
    signing_certs = certs if issuer == "sandbox" else upstream
    if issuer == "untrusted":
        signing_certs = tmp_path / "untrusted"
        _make_ca(signing_certs)

    fixture_root = tmp_path / "http"
    host = "registry.hermes.test"
    (fixture_root / host).mkdir(parents=True)
    manifest = b'{"name":"sandbox-tls-probe","version":"1.0.0"}'
    with tarfile.open(fixture_root / host / "probe.tgz", "w:gz") as archive:
        entry = tarfile.TarInfo("package/package.json")
        entry.size = len(manifest)
        archive.addfile(entry, io.BytesIO(manifest))

    # Import and run the production proxy handler on an ephemeral loopback port.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "proxy.py",
            str(fixture_root),
            str(signing_certs),
            str(certs / "real-ca.pem"),
        ],
    )
    spec = importlib.util.spec_from_file_location("sandbox_proxy", ASSETS / "proxy.py")
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            proxy.handle(self.request)

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy_url = f"http://127.0.0.1:{server.server_address[1]}"
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        (install_dir / "package.json").write_text(
            json.dumps({
                "name": "installer-tls-probe",
                "private": True,
                "dependencies": {"sandbox-tls-probe": f"https://{host}/probe.tgz"},
            }),
            encoding="utf-8",
        )
        managed_bin = tmp_path / "home" / "bin"
        managed_bin.mkdir(parents=True)
        uv = managed_bin / "uv"
        uv.write_text("#!/bin/sh\necho 'uv probe'\n", encoding="utf-8")
        uv.chmod(0o755)
        try:
            result = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts" / "install.sh"),
                    "--stage",
                    "node-deps",
                    "--json",
                    "--skip-browser",
                    "--skip-computer-use",
                ],
                cwd=REPO_ROOT,
                env={
                    **environment,
                    "HERMES_HOME": str(tmp_path / "home"),
                    "HERMES_INSTALL_DIR": str(install_dir),
                    "HTTP_PROXY": proxy_url,
                    "HTTPS_PROXY": proxy_url,
                    "ALL_PROXY": proxy_url,
                    "npm_config_cache": str(tmp_path / "npm-cache"),
                    "npm_config_userconfig": str(tmp_path / "no-npmrc"),
                    "npm_config_audit": "false",
                    "npm_config_fund": "false",
                    "npm_config_ignore_scripts": "true",
                    "npm_config_fetch_retries": "0",
                    "npm_config_fetch_timeout": "5000",
                },
                capture_output=True,
                text=True,
                timeout=20,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)

    stage = json.loads(result.stdout.splitlines()[-1])
    installed = install_dir / "node_modules" / "sandbox-tls-probe" / "package.json"
    npm_logs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "npm-cache" / "_logs").glob("*.log")
    )
    if issuer == "untrusted":
        assert result.returncode != 0
        assert stage["ok"] is False
        assert not installed.exists()
        assert "Node.js dependencies installed" not in result.stdout
        assert any(
            error in npm_logs
            for error in (
                "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
                "SELF_SIGNED_CERT_IN_CHAIN",
            )
        ), npm_logs
    else:
        assert result.returncode == 0, result.stdout + result.stderr + npm_logs
        assert stage["ok"] is True
        assert (
            json.loads(installed.read_text(encoding="utf-8"))["name"]
            == "sandbox-tls-probe"
        )
