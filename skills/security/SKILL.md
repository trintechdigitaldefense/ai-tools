---
name: security
description: "Write secure code, audit for vulnerabilities, and follow security best practices using bash, read_file, and edit_file."
---
# Security

Write secure code, audit for vulnerabilities, and follow security best practices using bash, read_file, and edit_file.

## Secrets Management

**NEVER hardcode secrets in source code.** This includes API keys, passwords, tokens, and private keys.

```python
# BAD
API_KEY = "sk-abc123secret"
# GOOD
import os
API_KEY = os.environ["API_KEY"]
```

Store secrets in `.env` files (never committed) or environment variables. Scan for leaks before committing:
```
bash: grep -rn "password\|secret\|api_key\|token\|private_key" --include="*.py" --include="*.js" .
bash: grep -rn "sk-\|ghp_\|AKIA" --include="*.py" --include="*.js" .
```

Ensure `.gitignore` includes `.env`, `*.pem`, and `credentials.json`.

## Input Validation

Never trust data from users, APIs, or files. Validate before using it.

```python
# BAD
page = int(request.args["page"])
# GOOD
page = int(request.args.get("page", 1))
if page < 1 or page > 1000:
    raise ValueError("page out of range")
```

For web APIs, use a validation library (Pydantic, zod, joi) to enforce schemas on all inputs.

## Injection Prevention

### SQL Injection
```python
# BAD -- SQL injection via name
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
# GOOD -- parameterized query
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
# GOOD -- ORM
session.query(User).filter(User.name == name).first()
```

### Command Injection
```python
# BAD
os.system(f"cat {filename}")
# GOOD -- use library functions, not shell
content = Path(filename).read_text()
# If shell is unavoidable, use list form
subprocess.run(["cat", filename])               # no shell=True
```

### Cross-Site Scripting (XSS)
Escape all user content before rendering in HTML. Use templating engines (Jinja2, React JSX) that auto-escape by default. Never use `dangerouslySetInnerHTML` or `| safe` with untrusted data.

## Authentication

### Password Hashing
Never store plaintext passwords. Never use MD5 or SHA1 for passwords.

```python
# bcrypt
from bcrypt import hashpw, gensalt, checkpw
hashed = hashpw(password.encode(), gensalt())
valid = checkpw(attempt.encode(), hashed)
```

### Token Security
- Generate tokens with `secrets.token_urlsafe(32)` -- never with `random`
- Set short expiration on JWTs (15-30 min for access tokens)
- Always validate JWT signature and expiration before trusting claims

## File Safety

Validate that file paths stay within allowed directories to prevent directory traversal:

```python
from pathlib import Path
base = Path("/uploads").resolve()
target = (base / user_input).resolve()
if not target.is_relative_to(base):
    raise ValueError("path traversal blocked")
```

```
bash: chmod 600 secrets.env                     # owner read/write only
bash: chmod 700 ~/.ssh                          # owner only
```

Never serve files from arbitrary paths. Restrict to a known safe directory.

## Dependencies

Audit dependencies regularly for known vulnerabilities:
```
bash: pip audit                                 # Python (install pip-audit first)
bash: npm audit                                 # JavaScript
bash: npm audit --audit-level=high              # only high/critical
```

Pin dependency versions in production. Update regularly -- stale deps accumulate vulnerabilities.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Debug mode in production | Set `DEBUG=False`, `NODE_ENV=production` |
| Verbose error messages | Return generic errors to users, log details server-side |
| CORS allowing `*` | Restrict to specific origins |
| No rate limiting | Add rate limits on auth endpoints and APIs |
| Secrets in git history | Rotate immediately, use `git filter-repo` to clean |
| HTTP in production | Always HTTPS, redirect HTTP to HTTPS |

## Security Checklist

Run through before shipping code:

- [ ] No hardcoded secrets -- all from environment variables
- [ ] `.env` and credential files in `.gitignore`
- [ ] All user input validated and sanitized
- [ ] SQL uses parameterized queries or ORM
- [ ] No shell commands with user-controlled input
- [ ] Passwords hashed with bcrypt or argon2
- [ ] Tokens from `secrets` module, not `random`
- [ ] File paths validated against directory traversal
- [ ] Dependencies audited: `bash: pip audit` / `bash: npm audit`
- [ ] Debug mode off, error messages generic
- [ ] CORS restricted to known origins

## Tips

- Security is not a feature you add later -- build it in from the start
- When in doubt, deny by default and whitelist explicitly
- If you find a vulnerability while working on other tasks, fix it immediately or flag it
- Use `read_file` to audit existing code for the patterns above before making changes
