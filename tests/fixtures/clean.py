# Clean sample — the scanner must report ZERO findings for this file.
import hashlib
import secrets
import subprocess
from html import escape


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def run(cmd_args: list[str]) -> None:
    subprocess.run(cmd_args, check=True)   # argv list, no shell execution


def render(user_name: str) -> str:
    return f"<p>{escape(user_name)}</p>"   # escaped output
