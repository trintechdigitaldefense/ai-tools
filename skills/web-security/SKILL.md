---
name: web-security
description: Web application security auditing, hardening, and penetration testing for deployed infrastructure
---

# Web Security

Security auditing and hardening for deployed web applications. Covers OWASP Top 10 detection, security headers, CORS, rate limiting, HTTPS, cookies, API security, and penetration testing basics.

## Security Header Audit

```
bash: curl -sI https://TARGET | grep -iE "^(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|x-xss)"
```

Missing headers = immediate action. Write an nginx config:

```
write_file: path=security-headers.conf
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

## OWASP Top 10 Quick Scans

**Broken Access Control**: `bash: grep -rn "req.params\.\(id\|userId\)" --include="*.ts" --include="*.py" | grep -v "auth\|session\|verify"`
**Hardcoded Secrets**: `bash: grep -rniE "(password|secret|api_key)\s*=\s*['\"]" --include="*.ts" --include="*.py" --include="*.env" .`
**Injection**: `bash: grep -rn "execute\|raw\|query" --include="*.py" --include="*.ts" . | grep -E "(f\"|%s|\$\{|\.format|\+.*req)"`
**XSS**: `bash: grep -rn "dangerouslySetInnerHTML\|v-html\|innerHTML" --include="*.tsx" --include="*.html" .`

## CORS Hardening

Test current CORS config:
```
bash: curl -sI -H "Origin: https://evil.com" https://TARGET/api/endpoint | grep -i "access-control"
```

If `Access-Control-Allow-Origin: *` appears on authenticated endpoints, that's a vulnerability. Never reflect arbitrary origins with credentials.

## HTTPS & TLS Audit

```
bash: openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer
bash: openssl s_client -connect TARGET:443 </dev/null 2>/dev/null | grep -E "Protocol|Cipher"
bash: curl -sI http://TARGET | head -5  # Should 301 to https
```

Caddy auto-HTTPS setup:
```
write_file: path=Caddyfile
example.com {
    reverse_proxy localhost:3000
    header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
}
```

## Rate Limiting

Nginx rate limiting:
```
write_file: path=rate-limit.conf
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
    }
}
```

FastAPI: `bash: pip install slowapi` then use `@limiter.limit("10/minute")` decorator.

## Cookie Security Checklist

Audit cookies:
```
bash: curl -sI https://TARGET/login -X POST -d "user=test&pass=test" | grep -i set-cookie
```

Every session cookie must have: `HttpOnly; Secure; SameSite=Lax` minimum. For cross-site auth: `SameSite=None; Secure`.

## API Security

JWT validation — check for common mistakes:
```
bash: grep -rn "verify\|decode\|jwt" --include="*.ts" --include="*.py" . | grep -vi "verify\|validate"
```

Never trust `alg: none`. Always validate `exp`, `iss`, `aud`. Rotate signing keys via environment variables, never hardcode.

## Full Security Audit Workflow

1. **Recon**: `bash: nmap -sV -sC -p 80,443,8080,3000 TARGET`
2. **TLS**: `bash: openssl s_client -connect TARGET:443 </dev/null 2>/dev/null | grep -E "Protocol|Cipher|Verify"`
3. **Headers**: `bash: curl -sI https://TARGET | grep -iE "^(server|x-powered|strict|content-sec|x-frame)"`
4. **Ports**: `bash: nmap -p- --min-rate=1000 TARGET | grep open`
5. **Directories**: `bash: for p in admin api docs .env .git wp-admin; do echo -n "$p: "; curl -so /dev/null -w "%{http_code}" https://TARGET/$p; echo; done`
6. **SSL certs**: `bash: echo | openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -noout -checkend 2592000 && echo "Valid >30d" || echo "EXPIRING SOON"`

## Penetration Testing Basics

Directory enumeration:
```
bash: for w in admin api login dashboard config .env backup; do code=$(curl -so /dev/null -w "%{http_code}" "https://TARGET/$w"); [ "$code" != "404" ] && echo "$w -> $code"; done
```

SQL injection test (read-only detection):
```
bash: curl -s "https://TARGET/api/search?q=test'%20OR%201=1--" -o /dev/null -w "%{http_code}"
```

Check for exposed `.git`:
```
bash: curl -sI https://TARGET/.git/HEAD | head -3
```

Always get written authorization before testing. Document findings with severity ratings (Critical/High/Medium/Low).
