# Security policy

Please report vulnerabilities through the repository's
[private vulnerability reporting form](https://github.com/optima-manent/ABCurves-Capture/security/advisories/new)
before opening a public issue. Include the affected version, reproduction steps,
and whether the issue can expose unrelated USB data, elevate more code than the
capture helper, escape a session/archive path, or corrupt a published bundle.

Security-sensitive boundaries include:

- the normal-user to elevated-helper command and capability files;
- exact USB address and certified endpoint filtering;
- native path and device-identity sanitization;
- bounded capture queues and parser lengths;
- shared writer/exclusive recovery leases and reparse-point rejection;
- atomic session publication and checksum validation;
- ZIP member containment, duplication, traversal, compressed/expanded extent,
  stream-termination, CRC, and sealed-session checksum checks.

Do not attach a real participant session to a public issue. Use synthetic data
or share evidence through a private channel.
