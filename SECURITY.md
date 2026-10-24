# Security

Report suspected vulnerabilities privately through this repository's GitHub
Security tab: **Report a vulnerability**. Include version, platform, a minimal
synthetic reproduction and the observed boundary failure. Do not publish secrets,
real environments or exploit data in public issues. This project has no paid
response SLA.

The current release receives fixes as maintainer capacity permits. Keep the trusted
Python runtime and installer patched. The scanner does not import a target's code
or execute its .pth files. Its reports contain local names/paths and should be
reviewed before sharing.

RECORD is untrusted metadata. Hash matches do not establish publisher identity,
authenticity or code safety. Scan a quiescent directory or snapshot. Link and file
identity checks do not provide process isolation against concurrent hostile
filesystem changes. External paths and linked/special files are not read.
