# Release preparation

No release-publishing workflow is enabled for this source preview. The test
workflow builds and checks the VSIX but does not retain or publish it as a
download. Repository visibility, Marketplace publication, asset upload and
public release creation each require a deliberate maintainer decision.

Before adding a manual release-build workflow, settle the public source
snapshot, actual download destination, version, required notices, branded-asset
rights and review responsibilities. Confirm the public source and package
checks pass on the exact intended commit, and retain the disclosed platform
limits in [release status](../docs/RELEASE_STATUS.md).

The future manual workflow should have this narrow contract:

1. Accept an explicit existing release tag and expected full public commit ID.
   Validate the tag's shape, resolve its commit and require an exact match before
   running package commands. Check that the extension version matches the tag.
   A tag's existence alone does not establish release approval or signing trust.
2. Check out that exact public commit with persisted credentials disabled and
   a read-only token. Require a clean tree. Use the same reviewed action pins,
   Python/Node versions and maintained packaging commands as public CI.
3. Run the public baseline and canonical VSIX package checks. Build a source
   archive from that exact public Git tree and calculate SHA-256 checksums for
   the source archive and canonical VSIX. Independently inspect archive members,
   included notices and absence of generated/runtime state.
4. Keep build results separate from publication. An explicitly reviewed later
   step may retain only the approved source archive, VSIX and checksum manifest;
   never upload a workspace, credentials, private diagnostics or test-results
   directory wholesale. Do not imply that checksums authenticate a publisher.

That future workflow must not create a tag, change repository visibility, upload
a release or publish to Marketplace as a side effect of a push or pull request.
No signing identity, provenance claim or public download URL is established by
this preparation note.
