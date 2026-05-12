# Contributing

Thank you for your interest in improving hestia-security.

## Before you open an issue or PR

- Test changes on a staging server first.
- Do not include secrets, private domains, real IP addresses, or screenshots with sensitive data.
- Keep changes focused and explain the security impact.

## Reporting issues

Please include:
- HestiaCP version
- Ubuntu/Debian version
- Relevant script name
- Exact command you ran
- The full error output or log snippet

## Pull requests

Please keep pull requests small and easy to review.

Good PRs usually include:
- A short description of the problem
- The fix and why it is needed
- Testing notes or command output
- Any compatibility notes for HestiaCP, nginx, or PHP-FPM

## Style

- Keep shell scripts POSIX-friendly where possible.
- Prefer clear variable names and concise comments.
- Avoid hardcoded personal data and environment-specific paths unless they are placeholders.
