# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo dual purpose

This repo carries **two parallel concerns** that share infrastructure but are otherwise independent:

1. **`proto` VPN scheme** — multi-protocol sing-box orchestration design (docs in `docs/`, deploy in `scripts/deploy.sh`, control-plane Python library in `src/proto/`: `subscription.py` + `rotation.py` + `bundle.py`).
2. **Composer lab** — local FastAPI backend (`src/proto/composer/`) + static web UI (`web/`) that lets you pick a sing-box inbound combination, spin up real sing-box server + client + tcpdump on loopback, and produce a pcap. For protocol-obfuscation experiments.

Both live in the same `pip install -e .` package. When working on the library do not pull composer deps into it; when working on composer do not bake in business logic that belongs in the library.

## Commands

```bash
# editable install (pulls fastapi/uvicorn/pydantic)
pip install -e .
pip install -e .[dev]                     # adds pytest, pytest-cov
pip install -e .[subscription]            # adds pynacl (Ed25519 signing)

# tests — README ships unittest-style; pyproject also wires pytest
python3 -m unittest discover tests        # canonical, ~72 cases
pytest tests/test_bundle.py               # single file
pytest tests/test_bundle.py::ValidatePayloadTests::test_valid_payload_passes  # single test

# composer backend — entry point is project root
python3 app.py                            # main entry (root-level FastAPI assembly)
uvicorn app:app --reload                  # dev mode with hot reload
# then open http://127.0.0.1:8787/web/composer.html

# sign a subscription token
python3 scripts/sign_subscription.py --help
```

## External dependencies (composer lab only)

- **sing-box** binary in `$PATH` — `composer.runner` shells out to `sing-box check` and `sing-box run`. Install from official tarball, not apt.
- **tcpdump** with capabilities — packet capture runs as the user, not root. One-time:
  `sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)`

## Composer architecture (strict layering)

The composer enforces a one-way dependency chain. Do not introduce backwards edges or shortcuts:

```
settings.py         constants only (ports, paths, protocol whitelist)
    ↑
config_builder.py   pure functions: render sing-box server/client JSON; no IO except secrets/time
    ↑
runner.py           ONLY place that touches subprocess / sing-box / tcpdump / curl;
                    owns the in-memory _RUNS registry and lifecycle
    ↑
routes.py           FastAPI APIRouter: HTTP↔runner translation, Pydantic models, exception mapping
    ↑
app.py (root)       app + middleware + lifespan + main(); imports routes via include_router
```

If a feature needs `subprocess`, it goes in `runner.py`. If it needs a port or path, it goes in `settings.py`. New endpoints go in `routes.py` — `app.py` should stay around 40 lines.

## Frontend split (web/)

`composer.html` is a slim shell. Logic lives in 2 separate JS files with an explicit boundary:

- `js/composer.js` — UI state, options, conflict checking, `buildConfig(state)`. Exposes only `window.buildConfig` and `window.state` at the bottom of the file (the *public API surface* between modules).
- `js/lab-client.js` — backend `fetch` calls only. Reads `window.buildConfig` / `window.state`; knows nothing about UI internals.

Removing the composer backend doesn't break `composer.js` — only the run/stop buttons in `lab-client.js` would be no-ops. Keep this contract.

## Runtime data layout

```
data/<run_id>/
├── server.json + client.json    (config snapshots, replayable)
├── <protocol-tag>.pcap          (binary capture, named after inbound tag)
└── logs/
    └── server.log + client.log + tcpdump.log + traffic.log
```

Everything for one experiment lives under a single `data/<run_id>/` directory — easy to zip, share, or delete a single run. `run_id` format: `YYYYMMDD-HHMMSS-XXXX` (4-hex suffix). The pcap filename is derived from the inbound's `tag` (or `type` if no tag) via `runner._pcap_filename`, e.g. `trojan-tcp-tls-utls.pcap`. All of `data/` is gitignored. PCAP HTTP route: `GET /runs/{run_id}/pcap`. Concurrent runs are not supported — the runner rejects a new `start_run` while one is active (HTTP 409).

## Conventions

- The composer lab supports 5 protocols: `shadowsocks` (ss2022), `trojan`, `hysteria2`, `vless` (incl. Reality), `vmess`. Adding a new protocol means: (1) add it to `SUPPORTED_PROTOCOLS` in `settings.py`; (2) add an injector in `_INJECTORS` and an outbound builder in `_OUTBOUNDS` in `config_builder.py`; (3) extend `runner._prepare_secrets` if the protocol needs a new credential type. Routes never change.
- TLS handling is automatic — `runner._gen_self_signed_cert` produces an `openssl`-signed cert per run for any non-Reality TLS protocol; clients use `tls.insecure: true` on loopback. Reality calls `sing-box generate reality-keypair` and the handshake target (default `www.microsoft.com:443`) requires real internet access from the host.
- Backend listens **only on 127.0.0.1**. Sing-box ports (8443/1080) are loopback. Never bind composer endpoints to 0.0.0.0 — this is a dev/research tool, not a service.
- Tests use `unittest` (`class XxxTests(unittest.TestCase)`). Don't migrate to pytest-style; pytest already discovers unittest cases via the `[tool.pytest.ini_options]` config.

## Do not run on dev machine

`scripts/deploy.sh` is for **VPS deployment** — it installs sing-box system-wide, requests ACME certs, modifies kernel sysctl, and edits firewall rules. Running it locally will trash your environment. It expects `sudo DOMAIN=<fqdn> bash scripts/deploy.sh` on a clean Linux server.
