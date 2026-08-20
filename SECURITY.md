# Security Policy

## Supported Versions

`saprfclib` is pre-1.0. Security fixes land on `main` and are released as a new patch
version. Only the latest released version is supported.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security problem.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/randomstr1ng/saprfclib/security/advisories/new)
(Security → Report a vulnerability), or by email to julian@petersohn.it.

Please include:

- affected version and Python version;
- a description of the issue and its impact;
- reproduction steps or a proof of concept, if you have one;
- whether the issue is already public anywhere.

You can expect an acknowledgement within 7 days and an assessment within 30 days.
Please give a reasonable window for a fix before public disclosure. Credit is given in
the advisory unless you ask otherwise.

## Scope

In scope:

- memory-unsafe or crash-inducing parsing of untrusted wire input (a malicious or
  compromised SAP gateway, SAProuter, or WebSocket peer);
- credential or session-token leakage into logs, exceptions, or tracebacks;
- TLS/SNC verification weaknesses in the transport layers;
- dependency vulnerabilities reachable through `saprfclib`.

Out of scope:

- vulnerabilities in SAP systems themselves — report those to SAP;
- misconfiguration of an SAP system this library connects to;
- issues requiring the attacker to already control the machine running `saprfclib`;
- results from automated scanners with no demonstrated impact.

## Handling Credentials

`saprfclib` accepts SAP credentials, SNC material, and session tokens. It is designed
never to write them to a log record at any level. If you observe a credential in log
output, an exception message, or a traceback, treat it as a security issue and report
it privately.

Never attach a pcap, log, or test fixture containing real credentials or customer data
to an issue or pull request.
