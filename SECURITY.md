# Security Policy

## Supported Versions

Security fixes ship in a new release of the latest major version. We do not backport them to older majors.

| Version | Security fixes |
|---------|----------------|
| 14.x    | Yes            |
| < 14.0  | No. Update to the latest release |

To update on Linux or macOS, run `adscan update`. On Windows, download the latest `adscan.exe` from the [releases page](https://github.com/ADScanPro/adscan/releases/latest).

## Reporting a Vulnerability

Do not open public issues for vulnerabilities, exposed secrets, bypasses, or unsafe exploitation behavior.

Email hello@adscanpro.com with:

- Affected ADscan version
- Minimal reproduction steps
- Expected impact
- Logs or screenshots with secrets removed
- Whether the issue affects LITE, PRO, docs, Docker images, or the PyPI launcher

## Response Timeline

We acknowledge valid reports within **72 hours** and aim to ship fixes within **14 days** for critical vulnerabilities. We coordinate fixes privately when disclosure could put users or customers at risk.

## Safe Disclosure

ADscan is a pentesting tool. Reports involving third-party systems must only include evidence from environments you are authorized to test.
