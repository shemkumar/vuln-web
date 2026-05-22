# OWASP Vulnerable Mixed Stack SAST Test Lab

This repository is intentionally vulnerable and exists only for local SAST, SCA, IaC, secret scanning, and DevSecOps pipeline validation. Do not deploy it to the internet or use it as application boilerplate.

## Stack coverage

- Node.js / Express API
- Python / Flask API
- Java / Spring-style controller code
- PHP legacy endpoint
- Browser frontend JavaScript
- Docker, Kubernetes, Terraform, GitHub Actions examples

## OWASP 2021 mapping

| OWASP category | Example weakness | Files |
|---|---|---|
| A01 Broken Access Control | IDOR, missing admin enforcement | `node-express/src/server.js`, `python-flask/app.py` |
| A02 Cryptographic Failures | MD5/SHA1, hardcoded keys, disabled TLS verification | `node-express/src/server.js`, `python-flask/app.py`, `java-spring/.../CryptoService.java` |
| A03 Injection | SQL injection, command injection, LDAP-style concatenation | `node-express/src/server.js`, `python-flask/app.py`, `php-legacy/index.php`, `java-spring/.../VulnController.java` |
| A04 Insecure Design | Predictable reset token, business logic bypass | `node-express/src/server.js`, `python-flask/app.py` |
| A05 Security Misconfiguration | Debug mode, permissive CORS, privileged container, public bucket | `python-flask/app.py`, `infra/Dockerfile`, `infra/k8s.yaml`, `infra/main.tf` |
| A06 Vulnerable and Outdated Components | Intentionally old package versions | `node-express/package.json`, `python-flask/requirements.txt` |
| A07 Identification and Authentication Failures | Weak password handling, insecure JWT secret | `node-express/src/server.js`, `python-flask/app.py` |
| A08 Software and Data Integrity Failures | Unsafe deserialization, unpinned action | `python-flask/app.py`, `.github/workflows/insecure-ci.yml` |
| A09 Security Logging and Monitoring Failures | Sensitive data logged, swallowed errors | `node-express/src/server.js`, `python-flask/app.py` |
| A10 SSRF | User-controlled URL fetch | `node-express/src/server.js`, `python-flask/app.py` |

## Suggested scanner signals

This lab intentionally includes patterns for SAST, SCA, IaC scanning, container scanning, secret scanning, and CI/CD workflow scanning. The examples are compact so scanners can attribute findings clearly.

## Safety note

The code uses fake credentials and intentionally unsafe constructs. Treat every finding as expected. Never expose this repository as a running service outside an isolated test environment.
# vuln-web
