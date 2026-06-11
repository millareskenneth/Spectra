# Security Rules (Functions) Progress

This checklist is automatically updated by `scripts/sync-progress.ts`.

## Request Rules
- [x] REQ-001: API key or secret in URL query parameter
- [x] REQ-002: Password in URL query parameter
- [x] REQ-003: AWS credential pattern detected
- [x] REQ-004: Authorization token sent over plain HTTP
- [x] REQ-005: Private key pattern in request body

## Response Rules
- [x] RES-001: Stack trace in response body
- [x] RES-002: Internal server paths exposed
- [x] RES-003: Auth endpoint returns sensitive fields
- [x] RES-004: Response contains excessive user PII
- [x] RES-005: DB internals leaked
- [x] RES-006: Server technology fingerprint
- [x] RES-007: Response returns full DB row on login/profile

## Header Rules
- [x] HDR-001: Missing HSTS
- [x] HDR-002: Missing CSP
- [x] HDR-003: Missing X-Content-Type-Options
- [x] HDR-004: Missing X-Frame-Options
- [x] HDR-005: X-Powered-By or Server header reveals stack

## JWT Rules
- [x] JWT-001: alg: none
- [x] JWT-002: missing exp claim
- [x] JWT-003: sensitive PII in payload
- [x] JWT-004: sent over plain HTTP

## Cookie Rules
- [x] COK-001: missing Secure flag
- [x] COK-002: missing HttpOnly flag
- [x] COK-003: missing SameSite attribute

## TLS Rules
- [x] TLS-001: HTTPS endpoint falls back to HTTP redirect
- [ ] TLS-002: Certificate pinning detected
