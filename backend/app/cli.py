"""Operator commands.

  python -m app.cli create-staff --email admin@example.org --role admin   (password read from stdin / prompt)
  python -m app.cli purge
  python -m app.cli export-openapi path.json
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys


async def _create_staff(email: str, role: str, password: str) -> None:
    from app.api.deps import load_user_by_email
    from app.core.security import hash_password, password_problems
    from app.db.models import Subscription, User, UserPreferences
    from app.db.session import get_sessionmaker

    problems = password_problems(password, email)
    if problems:
        sys.exit("Password " + "; ".join(problems))
    async with get_sessionmaker()() as db:
        if await load_user_by_email(db, email):
            sys.exit("User already exists")
        u = User(email=email.lower(), password_hash=hash_password(password), role=role, display_name=role.capitalize())
        u.preferences = UserPreferences()
        u.subscription = Subscription(plan="free")
        db.add(u)
        await db.commit()
    print(f"Created {role} {email}. Sign in and enable two-factor authentication before using staff features.")


async def _purge() -> None:
    from app.db.session import get_sessionmaker
    from app.services.analysis_service import purge_expired

    async with get_sessionmaker()() as db:
        print(await purge_expired(db))


def main() -> None:
    ap = argparse.ArgumentParser(prog="trustrelay")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-staff")
    c.add_argument("--email", required=True)
    c.add_argument("--role", choices=["admin", "support", "security"], required=True)
    sub.add_parser("purge")
    o = sub.add_parser("export-openapi")
    o.add_argument("path")
    args = ap.parse_args()
    if args.cmd == "create-staff":
        pw = sys.stdin.readline().rstrip("\n") if not sys.stdin.isatty() else getpass.getpass("Password: ")
        asyncio.run(_create_staff(args.email, args.role, pw))
    elif args.cmd == "purge":
        asyncio.run(_purge())
    elif args.cmd == "export-openapi":
        from app.main import app

        with open(args.path, "w") as f:
            json.dump(app.openapi(), f, indent=2, ensure_ascii=False)
            f.write("\n")


if __name__ == "__main__":
    main()
