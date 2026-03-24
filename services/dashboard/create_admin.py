#!/usr/bin/env python3
"""
Create or reset a dashboard admin user.

Usage (run inside the dashboard container):
    python create_admin.py <username> <password>

Environment variables:
    DATABASE_URL  — PostgreSQL connection string (required, set by Docker Compose)

Examples:
    docker exec thebox-dashboard python create_admin.py admin '<strong-password>'

If the username already exists the password is updated.
If it does not exist a new user is inserted.

Use a strong, unique password — at least 12 characters mixing letters, digits,
and symbols. Change it after the first login if desired.
"""

import sys
import os
import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <username> <password>", file=sys.stderr)
        sys.exit(1)

    username = sys.argv[1].strip()
    password = sys.argv[2]

    if not username:
        print("Error: username must not be empty.", file=sys.stderr)
        sys.exit(1)

    if not password:
        print("Error: password must not be empty.", file=sys.stderr)
        sys.exit(1)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("Error: DATABASE_URL environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    password_hash = generate_password_hash(password)

    try:
        conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    except psycopg2.OperationalError as exc:
        print(f"Error: could not connect to the database: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE users SET password_hash = %s, updated_at = NOW() WHERE username = %s",
                    (password_hash, username),
                )
                print(f"Password updated for existing user '{username}'.")
            else:
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, password_hash),
                )
                print(f"User '{username}' created successfully.")
        conn.commit()
    except psycopg2.Error as exc:
        print(f"Error: database operation failed: {exc}", file=sys.stderr)
        conn.rollback()
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
