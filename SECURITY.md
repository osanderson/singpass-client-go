# Security policy

This library handles authentication and personal data, so security reports
are taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through
[GitHub's private vulnerability reporting](https://github.com/osanderson/singpass-client-go/security/advisories/new)
(Security → Report a vulnerability). Include the affected version, a
description of the issue and its impact, and steps or code to reproduce.

You can expect an acknowledgement within a few days. Fixes are released as a
patch version with a GitHub security advisory crediting the reporter (unless
you'd rather not be named).

## Supported versions

The project is pre-1.0: only the **latest release** receives security fixes.

## Scope

In scope: this library (`singpass`, `myinfo`, `web`, `keyfile`) and the demo's
handling of keys and sessions. Vulnerabilities in [FAPIgo](https://github.com/idfoundry/fapigo)
itself should be reported to that project; issues in Singpass or Corppass
themselves to GovTech through its vulnerability disclosure programme.

This is an **unofficial** community library, not affiliated with or endorsed
by GovTech, Singpass or Corppass.
