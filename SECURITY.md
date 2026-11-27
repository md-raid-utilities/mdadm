# Security Policy

This is community-maintained project. We take security issues seriously
and appreciate coordinated disclosure from researchers and users.

## Supported Versions

Security fixes are provided for the latest released version on the `main`
branch. Older versions are not maintained; please retest on the latest `main`
before reporting.

Depending on the problem urgency, other more problem-driven action would be taken.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.** Public disclosure before a fix is available
puts users at risk.

Instead, use one of the following private channels:

1. **GitHub Private Vulnerability Reporting (preferred).**
   Navigate to the repository's
   [Security tab](https://github.com/md-raid-utilities/mdadm/security) and
   click **Report a vulnerability**. This opens a private advisory visible only
   to the reporter and the maintainers. See GitHub's guide on
   [privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
   for details.

2. **Email the maintainers.**
   If you cannot use GitHub's private reporting, send an encrypted or plain
   email [Maintainers team](https://github.com/md-raid-utilities/mdadm/blob/main/MAINTAINERS.md)

### What to include

To help us triage quickly, please include as much of the following as you can:

- A description of the issue and its impact.
- The affected component and version, the best is the commit.
- Steps to reproduce, a proof-of-concept, or a crash/backtrace.
- Any known mitigations or workarounds.
- Whether you intend to request a CVE.
- How you would like to be credited (or if you prefer to remain anonymous).

## Coordinated Disclosure

Our process is:

1. **Acknowledgment.** We aim to acknowledge new reports within a few business
   days. Because this is a volunteer-maintained project we cannot guarantee a
   strict SLA, but we will keep you informed of progress.
2. **Triage and fix.** We work with the reporter to confirm the issue, assess
   severity, and develop a fix in a private branch or GitHub security advisory.
3. **Embargo.** Please give us a reasonable time to prepare a fix and, where
   appropriate, to coordinate with Linux distributions before public
   disclosure. A typical embargo window is up to 90 days, shorter for
   already-public or actively-exploited issues.
4. **Release and advisory.** Once a fix is ready we publish a new release, a
   GitHub Security Advisory, and (when applicable) request a CVE. Reporters are
   credited unless they ask otherwise.