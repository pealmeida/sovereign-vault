"""sv_secrets.py — Sovereign Vault secrets loader with .env redundancy.

Python port of clients/node/sv-secrets.mjs. Use the vault as your primary
secrets manager with the local .env as an automatic fallback. Stdlib only
(Python >= 3.8). Never logs secret values.

Quick start:
    from sv_secrets import load_secrets
    source, vars = load_secrets(container="env-myproject")
    os.environ.update(vars)

Source switch (env var, no code change):
    SECRETS_SOURCE=auto   (default) vault first, fall back to .env on any failure
    SECRETS_SOURCE=vault  vault only; raise if unavailable
    SECRETS_SOURCE=env    local .env only

CLI:
    python sv_secrets.py --container env-myproject --out .env.runtime
    SECRETS_SOURCE=env python sv_secrets.py --container env-myproject --out .env.runtime

Knobs (env): SV_BIN, SV_TIMEOUT_MS (default 30000), SV_OTP, SV_CACHE_TTL_MS (default 0=off).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

def _default_bin() -> str:
    """Resolve the vault CLI cross-platform, no machine-specific paths:
    SV_BIN wins; else the repo build if this loader still lives in-tree;
    else rely on PATH (sovereign-vault / sovereign-vault.exe)."""
    override = os.environ.get("SV_BIN")
    if override:
        return override
    exe = "sovereign-vault.exe" if os.name == "nt" else "sovereign-vault"
    repo_bin = Path(__file__).resolve().parent.parent.parent / "target" / "release" / exe
    return str(repo_bin) if repo_bin.exists() else exe


DEFAULT_BIN = _default_bin()
DEFAULT_FILE = ".env"
DEFAULT_ENV_PATH = ".env"
DEFAULT_TIMEOUT_MS = int(os.environ.get("SV_TIMEOUT_MS") or 30000)
CACHE_DIR = Path(tempfile.gettempdir()) / "sv-secrets-cache"


def parse_dotenv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def read_from_vault(container, file=DEFAULT_FILE, bin=DEFAULT_BIN,
                    timeout_ms=DEFAULT_TIMEOUT_MS, otp=None) -> str:
    """Read+decode one file from a vault container via the mcp-stdio proxy.
    Returns plaintext. Raises on lock/deny/timeout/OTP. Vault must be unlocked;
    APPROVAL containers raise a desktop prompt."""
    if not container:
        raise ValueError("container is required")
    args = {"container": container, "file_name": file}
    if otp:
        args["otp"] = otp
    frame = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "vault.read", "arguments": args},
    })

    proc = subprocess.Popen(
        [bin, "mcp-stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    q: "queue.Queue[str]" = queue.Queue()

    def reader():
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                q.put(line)
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    try:
        proc.stdin.write(frame + "\n")  # type: ignore[union-attr]
        proc.stdin.flush()  # type: ignore[union-attr]
        # keep stdin open so the proxy stays alive until the response arrives
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            try:
                line = q.get(timeout=deadline - time.monotonic())
            except queue.Empty:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != 1 or "result" not in msg:
                continue
            result = msg["result"]
            text = (result.get("content") or [{}])[0].get("text", "")
            if result.get("isError"):
                raise RuntimeError(f"vault: {text}")  # includes otp_required
            payload = json.loads(text)
            b64 = payload.get("content_b64")
            if not b64:
                raise RuntimeError("vault response missing content_b64")
            return base64.b64decode(b64).decode("utf-8")
        raise TimeoutError(f"vault read timed out after {timeout_ms}ms")
    finally:
        try:
            proc.kill()
        except Exception:
            pass


# ── Session cache (opt-in) ─────────────────────────────────────────────────
# SECURITY TRADEOFF: caches decrypted secrets to a 0600 temp file for the TTL,
# partially defeating the vault. Off by default.
def _cache_path(container, file) -> Path:
    h = hashlib.sha256(f"{container} {file}".encode()).hexdigest()[:24]
    return CACHE_DIR / f"{h}.json"


def _read_cache(container, file, ttl_ms):
    if not ttl_ms or ttl_ms <= 0:
        return None
    p = _cache_path(container, file)
    try:
        metadata = p.lstat()
    except FileNotFoundError:
        return None
    if p.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        return None
    if os.name != "nt" and metadata.st_mode & 0o077:
        return None
    try:
        data = json.loads(p.read_text("utf-8"))
        if (time.time() * 1000 - data["ts"]) > ttl_ms:
            p.unlink(missing_ok=True)
            return None
        return data["vars"] if isinstance(data.get("vars"), dict) else None
    except Exception:
        return None


def _write_private_text(path: Path, text: str) -> None:
    parent = path.parent if str(path.parent) else Path(".")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent, text=True)
    temporary_path = Path(temporary)
    try:
        os.chmod(temporary_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def _write_cache(container, file, vars):
    try:
        CACHE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        cache_metadata = CACHE_DIR.lstat()
        if CACHE_DIR.is_symlink() or not stat.S_ISDIR(cache_metadata.st_mode):
            raise OSError("cache directory is not a real directory")
        if os.name != "nt":
            os.chmod(CACHE_DIR, 0o700)
        p = _cache_path(container, file)
        _write_private_text(p, json.dumps({"ts": time.time() * 1000, "vars": vars}))
    except Exception:
        pass  # best-effort


def clear_cache(container=None, file=DEFAULT_FILE):
    import shutil
    try:
        if container:
            _cache_path(container, file).unlink(missing_ok=True)
        else:
            shutil.rmtree(CACHE_DIR, ignore_errors=True)
    except Exception:
        pass


def _read_env_file(env_path=DEFAULT_ENV_PATH) -> str:
    p = Path(env_path)
    if not p.exists():
        raise FileNotFoundError(f"no local fallback at {env_path}")
    return p.read_text("utf-8")


def load_secrets(container, file=DEFAULT_FILE, env_path=DEFAULT_ENV_PATH,
                 source=None, bin=DEFAULT_BIN, timeout_ms=DEFAULT_TIMEOUT_MS,
                 otp=None, cache_ttl_ms=None):
    """Return (source, vars). Honors SECRETS_SOURCE (auto|vault|env)."""
    source = source or os.environ.get("SECRETS_SOURCE") or "auto"
    otp = otp if otp is not None else os.environ.get("SV_OTP")
    cache_ttl_ms = cache_ttl_ms if cache_ttl_ms is not None else int(os.environ.get("SV_CACHE_TTL_MS") or 0)

    if source == "env":
        return "env", parse_dotenv(_read_env_file(env_path))

    cached = _read_cache(container, file, cache_ttl_ms)
    if cached is not None:
        return "cache", cached

    def try_vault():
        return parse_dotenv(read_from_vault(container, file, bin, timeout_ms, otp))

    if source == "vault":
        vars = try_vault()
        _write_cache(container, file, vars)
        return "vault", vars

    # auto
    try:
        vars = try_vault()
        _write_cache(container, file, vars)
        return "vault", vars
    except Exception:
        # The vault error can include provider-controlled content, so never log it.
        sys.stderr.write(f"[sv-secrets] vault unavailable; falling back to {env_path}\n")
        return "env", parse_dotenv(_read_env_file(env_path))


def _to_dotenv(vars: dict[str, str]) -> str:
    return "\n".join(f"{k}={v}" for k, v in vars.items()) + "\n"


def _main(argv):
    def get(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None

    container = get("--container")
    file = get("--file") or DEFAULT_FILE
    out = get("--out")
    source = get("--source") or os.environ.get("SECRETS_SOURCE") or "auto"
    cache_ttl_ms = int(get("--cache-ttl")) if get("--cache-ttl") else int(os.environ.get("SV_CACHE_TTL_MS") or 0)

    if "--clear-cache" in argv:
        clear_cache(container, file)
        sys.stderr.write("[sv-secrets] cache cleared\n")
        if not container:
            return 0
    if not container:
        sys.stderr.write("usage: python sv_secrets.py --container <name> [--file .env] "
                         "[--source auto|vault|env] [--out path] [--cache-ttl <ms>] [--clear-cache]\n")
        return 2
    if not out:
        sys.stderr.write("[sv-secrets] refusing to write secret values to stdout; pass --out <path>\n")
        return 2
    try:
        source, vars = load_secrets(container=container, file=file, source=source, cache_ttl_ms=cache_ttl_ms)
        sys.stderr.write(f"[sv-secrets] {len(vars)} keys from {source}\n")
        text = _to_dotenv(vars)
        _write_private_text(Path(out), text)
        sys.stderr.write(f"[sv-secrets] wrote {out}\n")
        return 0
    except Exception:
        # Parsing/provider errors can contain secret-bearing file content.
        sys.stderr.write("[sv-secrets] ERROR failed to load or write secrets\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
