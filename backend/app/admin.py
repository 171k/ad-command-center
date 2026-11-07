"""Admin CLI:  python -m app.admin <command>

Commands:
  status                      Show account / data status
  set-password [--password P] Set or rotate the shared password (prompts if omitted)
  seed-library                Load the curated script library (if empty)
  create-sensor <name>        Create a sensor and print its one-time token
  demo-data                   Load demo services + synthetic SOC traffic (clearly labelled)
"""
from __future__ import annotations

import argparse
import getpass
import sys

from . import auth, db, seed
from .security import new_token, token_hash
from .soc.correlate import ingest_batch
from .soc import normalize


def _init():
    db.run_migrations()


def cmd_status(_):
    _init()
    print("Account configured:", auth.account_is_setup())
    for t in ("services", "findings", "scripts", "events", "offenses", "sensors"):
        print(f"  {t}: {db.query_one(f'SELECT COUNT(*) c FROM {t}')['c']}")


def cmd_set_password(args):
    _init()
    pw = args.password or getpass.getpass("New shared password (min 10 chars): ")
    if not args.password:
        if pw != getpass.getpass("Confirm: "):
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    try:
        auth.set_password(pw)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    print("Password set.")


def cmd_seed_library(_):
    _init()
    n = seed.seed_library()
    print(f"Inserted {n} curated scripts." if n else "Library already populated (no change).")


def cmd_create_sensor(args):
    _init()
    tok = new_token()
    cur = db.execute("INSERT INTO sensors(name, token_hash, kind) VALUES (?,?,?)",
                     (args.name, token_hash(tok), "suricata"))
    print(f"Sensor '{args.name}' created (id={cur.lastrowid}).")
    print("One-time token (store securely, not recoverable):")
    print(f"  {tok}")


def cmd_demo_data(_):
    _init()
    # demo services
    if not db.query_one("SELECT id FROM services WHERE host='10.10.0.5'"):
        db.execute("INSERT INTO services(name, host, port, protocol, description, owner, authorized) "
                   "VALUES ('Demo web (ours)','10.10.0.5',8080,'http','DEMO service',?,0)", ("ours",))
    seed.seed_library()
    items = [(normalize.from_eve(r), r) for r in seed.demo_events()]
    items = [(e, r) for e, r in items if e]
    summary = ingest_batch(items)
    print("Demo data loaded (clearly labelled as DEMO):", summary)


def main(argv=None):
    p = argparse.ArgumentParser(prog="app.admin")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sp = sub.add_parser("set-password"); sp.add_argument("--password"); sp.set_defaults(fn=cmd_set_password)
    sub.add_parser("seed-library").set_defaults(fn=cmd_seed_library)
    cs = sub.add_parser("create-sensor"); cs.add_argument("name"); cs.set_defaults(fn=cmd_create_sensor)
    sub.add_parser("demo-data").set_defaults(fn=cmd_demo_data)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
