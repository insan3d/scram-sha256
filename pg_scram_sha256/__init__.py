"""
Generate PostgreSQL-compatible SCRAM-SHA-256 password verifiers.

This tool computes SCRAM-SHA-256 secrets in the exact format used by PostgreSQL
and PgBouncer. Output value can be safely placed into PostgreSQL's `pg_authid`
catalog (via `ALTER USER ... PASSWORD`) or into PgBouncer's `userlist.txt`.
"""

__prog__ = "scram-sha256"
__version__ = "1.0.0"
__status__ = "Release"
__author__ = "Alexander Pozlevich"
__email__ = "apozlevich@gmail.com"
