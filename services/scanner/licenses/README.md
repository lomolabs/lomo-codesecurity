# Scanner license texts

These unmodified texts match `binary.license.source_sha256` in the reviewed
`scanner-tools.lock.json`. The image build verifies each text and installs this
index, all eight texts and the two reviewed upstream attribution files at
`/usr/local/share/kodesec/licenses`.

| Tool | License identifier in the lock | Included text | Source |
| --- | --- | --- | --- |
| trivy | Apache-2.0 | [trivy.txt](trivy.txt) | [Pinned upstream text](https://raw.githubusercontent.com/aquasecurity/trivy/40c73e5d6166dcc0346a1ab4e94499d1572854e4/LICENSE) |
| gitleaks | MIT | [gitleaks.txt](gitleaks.txt) | [Pinned upstream text](https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE) |
| opengrep | LGPL-2.1-or-later | [opengrep.txt](opengrep.txt) | [Pinned upstream text](https://raw.githubusercontent.com/opengrep/opengrep/3bd8e95fea8992e15ea2451286dd1cb145e57add/LICENSE) |
| bearer | Elastic-2.0 | [bearer.txt](bearer.txt) | [Pinned upstream text](https://raw.githubusercontent.com/Bearer/bearer/814948ecc198a743b13a75a6bfd4688514285220/LICENSE.txt) |
| grype | Apache-2.0 | [grype.txt](grype.txt) | [Pinned upstream text](https://raw.githubusercontent.com/anchore/grype/b5fa92bbcbef655497e3be840a2f718380e2cdd3/LICENSE) |
| checkov | Apache-2.0 | [checkov.txt](checkov.txt) | [Pinned upstream text](https://raw.githubusercontent.com/bridgecrewio/checkov/fb3e4ed6d57555820dbf7b1b02744a356333e2f1/LICENSE) |
| trufflehog | AGPL-3.0-or-later | [trufflehog.txt](trufflehog.txt) | [Pinned upstream text](https://raw.githubusercontent.com/trufflesecurity/trufflehog/6f3c981e7b77f235fd2702dd74af25fc4b72bf11/LICENSE) |
| syft | Apache-2.0 | [syft.txt](syft.txt) | [Pinned upstream text](https://raw.githubusercontent.com/anchore/syft/2293641e3bd628a01bb37639318d62c0ebe89b39/LICENSE) |

The unmodified [Trivy NOTICE](trivy.NOTICE) and [Opengrep COPYRIGHT](opengrep.COPYRIGHT)
retain the upstream holders' attribution and licensing statements. Their bytes
and source revisions are checked during the image build. A tool source update
requires renewed notice review. Sources:
[Trivy NOTICE](https://raw.githubusercontent.com/aquasecurity/trivy/40c73e5d6166dcc0346a1ab4e94499d1572854e4/NOTICE)
and [Opengrep COPYRIGHT](https://raw.githubusercontent.com/opengrep/opengrep/3bd8e95fea8992e15ea2451286dd1cb145e57add/COPYRIGHT).
Opengrep's COPYRIGHT names LGPL version 2.1 while the existing lock records
LGPL-2.1-or-later; the release audit must resolve that distinction. This packaging
change preserves both upstream texts and does not change the lock's expression.

Lomo's Apache-2.0 license does not replace these licenses. The modified Bearer
binary also includes its modification notice, build receipt and recipe at
`/usr/local/share/kodesec/builds/bearer`. Its source recipe and patch are included
under `services/scanner/bearer` in the Lomo source distribution.

This directory covers the eight top-level scanner license texts and these two
upstream attribution files. It is not a
complete dependency license inventory, source bundle, redistribution review or
image SBOM. Final release review must also account for the exact scanner
sources and modifications, embedded dependencies, Python packages, operating
system packages and scanner rules/data. Do not claim that this index alone
clears those release gates.
