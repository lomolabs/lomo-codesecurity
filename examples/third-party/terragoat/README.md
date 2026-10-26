# TerraGoat: scan-only example

This small [TerraGoat](https://github.com/bridgecrewio/terragoat) subset is
intentionally insecure Terraform for testing policy-as-code scanners such as
Checkov. **Scan these files; never run Terraform, Docker commands, repository
tasks, or deployment scripts from them.** No dependency installation is needed.
The subset is intentionally incomplete for deployment. Any credentials in it
are upstream synthetic examples, not application configuration.

Open [the example workspace](../../security-demo.code-workspace), prepare
scanners, then choose **CodeSecurity: Scan Workspace Folders…**. Select this
folder and/or the existing vulnerable demo. Each folder has its own project,
scan, findings and job; a result for one never proves coverage of the other.

Source: `bridgecrewio/terragoat` commit
[`729f8da62c6a85ce4af5ad3d123de97776d954c4`](https://github.com/bridgecrewio/terragoat/commit/729f8da62c6a85ce4af5ad3d123de97776d954c4).
Only `terraform/aws/s3.tf`, `ecr.tf`, `consts.tf` and the Apache-2.0
[license](LICENSE) are imported. Original attribution is retained. The only
local source changes are a scan-only warning and normalized final newlines.
[provenance.json](provenance.json) records upstream and vendored hashes.

This fixture is for local scanning only. It does not authorize external
Advisor transmission or expand any source mount.
