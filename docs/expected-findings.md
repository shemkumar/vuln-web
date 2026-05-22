# Expected Findings Checklist

Use this checklist to validate SAST/SCA/IaC/secret-scanning coverage.

- SQL injection in Node, Python, Java, and PHP.
- Command injection in Node, Python, Java, and PHP.
- Reflected or DOM XSS in Node, PHP, and frontend JavaScript.
- Unsafe deserialization in Python and Java.
- SSRF in Node and Python.
- Weak cryptography: MD5, SHA1, AES ECB, hardcoded keys.
- Broken access control: IDOR and missing admin enforcement.
- Security misconfiguration: debug mode, permissive CORS, insecure cookies, privileged containers, public S3 ACL, open security group.
- Dependency risks: old npm, pip, Maven dependencies.
- CI/CD risks: unpinned actions, `curl | bash`, excessive workflow permissions.
