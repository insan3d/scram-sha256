# scram-sha256

Generate and verify PostgreSQL-compatible SCRAM-SHA-256 password verifiers in exactly the same format that PostgreSQL stores inside `pg_authid` and that PgBouncer expects inside `userlist.txt`.

The tool uses Python’s built-in `hashlib`, `hmac`, and `pbkdf2_hmac` and does not depend on OpenSSL. All cryptographic operations strictly follow [RFC7677](https://datatracker.ietf.org/doc/html/rfc7677) and PostgreSQL's `src/common/scram-common.c` logic.

## Usage

### Generate SCRAM verifier

```sh
scram-sha256 mypassword
```

Example output:

```plain
SCRAM-SHA-256$4096:jJtPFbKh8Kbl0JUdhJLiRg==$rLZuvwE5U7S05GbFizTJt8vlTblsBF0o9g1wxI6O8IU=$Bg4xIDb0tsYY6MZU1eQDp6ccq4ImjgJ63NMI0rKq/Zs=
```

#### With custom salt (HEX):

```sh
scram-sha256 -s 00112233445566778899AABBCCDDEEFF mypassword
```

#### With custom salt (BASE64):

```sh
scram-sha256 -s ABBCEEV1sZRbI9twee59Ww== mypassword
```

#### With custiom iteration count

```sh
scram-sha256 -i 8192 mypassword
```

### Verify password

```sh
scram-sha256 mypassword "SCRAM-SHA-256$4096:..."
```

### Using with PostgreSQL

```sql
ALTER ROLE testuser PASSWORD 'SCRAM-SHA-256$4096:...';
```

### Using with PgBouncer

Inside `userlist.txt`:

```plain
"username" "SCRAM-SHA-256$4096:..."
```

### API Reference

```python
from scram_sha256 import scram_sha256, verify_scram_sha256

v = scram_sha256(b"mypassword", iterations=4096, salt=None)
verify_scram_sha256("mypassword", v)  # True
verify_scram_sha256("badpassword", v)  # False
```

## Notes

- Salt must be 16 bytes, same as PostgreSQL.
- Iteration count must be at least 4096 (default), per PostgreSQL defaults.
- The tool uses `hmac.compare_digest()` for constant-time comparison.
- No external C or OpenSSL dependencies, so safe in minimal containers.

## License

MIT license.
