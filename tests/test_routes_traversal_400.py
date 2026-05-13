"""Cover the path-traversal guard in routes.py GET /runs/{run_id}/pcap.

Line 86 raises HTTPException(400) when (DATA_DIR / run_id).resolve() escapes
DATA_DIR.  URL-based ".." attempts are normalised by the HTTP client before
they reach the handler, so the only reliable trigger is a symlink whose
resolve() target lies outside DATA_DIR.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from proto.composer.routes import router


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class PathTraversalSymlinkTests(unittest.TestCase):
    """Symlink whose resolved path escapes DATA_DIR must return 400."""

    def test_symlink_outside_data_dir_returns_400(self) -> None:
        from proto.composer import routes as _routes_mod

        with tempfile.TemporaryDirectory() as data_dir_str, \
                tempfile.TemporaryDirectory() as outside_str:
            data_dir = Path(data_dir_str)
            outside = Path(outside_str)

            # Create a symlink inside DATA_DIR that points to a directory
            # outside DATA_DIR.  The link name is a plain string with no '..',
            # so the URL is well-formed and won't be normalised by the client.
            link = data_dir / "evil-link"
            os.symlink(outside, link)

            with patch.object(_routes_mod, "DATA_DIR", data_dir):
                client = _make_client()
                resp = client.get("/runs/evil-link/pcap")

        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid run_id", resp.text)


if __name__ == "__main__":
    unittest.main()
