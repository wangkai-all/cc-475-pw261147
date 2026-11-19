"""Entry point: python -m app.server [--port 8000] [--seed]"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import ThreadingHTTPServer

from . import store
from .api import Handler
from .engine import history_seed, lake


def bootstrap(force_reseed: bool = False) -> dict:
    store.init_db()
    with store.db() as conn:
        lake.seed(conn, reset=force_reseed)
        history_seed.seed_history(conn, reset=force_reseed)
        conn.commit()
        return {
            "tables": conn.execute("SELECT COUNT(*) n FROM tables").fetchone()["n"],
            "executions": conn.execute("SELECT COUNT(*) n FROM executions").fetchone()["n"],
        }


def serve(port: int, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query history analyzer")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--seed", action="store_true", help="recreate the demo lake and history")
    parser.add_argument("--check", action="store_true", help="bootstrap and exit (for tests)")
    args = parser.parse_args(argv)

    stats = bootstrap(force_reseed=args.seed)
    print(json.dumps({"bootstrapped": stats, "data_dir": store.DATA_DIR}), flush=True)
    if args.check:
        return 0
    httpd = serve(args.port, args.host)
    print(f"serving on http://{args.host}:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
