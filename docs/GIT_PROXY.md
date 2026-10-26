# Optional Git Proxy

The default CodeSecurity stack scans local repositories directly. The Git proxy is an
optional Gitea profile for users who want a localhost Git landing zone before
forwarding to GitHub, GitLab, or another remote.

## Start

```bash
make up-git-proxy
make bootstrap-gitea
```

Open:

- Gitea UI: http://127.0.0.1:3000
- SSH: `ssh://git@127.0.0.1:2222/<owner>/<repo>.git`

For a disposable local smoke test:

```bash
make test-git-proxy
```

This creates a `kodesec-test` user, generates a throwaway SSH key beneath the
external owner state directory at `gitea-smoke/`, creates a private
`kodesec-smoke` repo, pushes a commit over SSH, and clones it back.

## Intended Workflow

1. Create a local repository in Gitea.
2. Add a deploy key or user SSH key.
3. Push from VS Code or terminal to localhost Gitea.
4. Let CodeSecurity scan the local checkout or future webhook integration.
5. Configure Gitea push mirrors to forward to the final remote.

## Why Gitea Is Optional

Most solo users want `register path -> scan -> review findings`. A required Git
proxy would slow first-run adoption. The proxy becomes useful when the user wants
local backups, mirrors, server-side hooks, or a private staging remote.

## Current Scope

**A failed CodeSecurity gate does not currently block Git commits or pushes.**
This profile is local hosting, not an enforced security proxy. Gate evaluation
and Git enforcement are different capabilities; see the
[push-protection gap and proposed design](GIT_PUSH_PROTECTION.md).

The profile starts Gitea with persistent volumes. Automated localhost smoke
bootstrap is included. Webhook setup and mirror configuration are planned
extension work.

Gitea service secrets and the disposable smoke password are generated into the
owner-only external runtime file. They are not exposed through the CodeSecurity
Settings API.
