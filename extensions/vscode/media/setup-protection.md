# Make push protection a deliberate choice

Review the repository’s scan gate, then use **Protect Pushes…** to request access and apply the local hook.

**Requested** is the saved policy. **Local hook** is the inspected clone state. They must match before setup is considered applied. Choosing Off is explicit and allows unchecked pushes from this clone.

When On, each push checks its exact outgoing committed content. Dirty edits, stale scans or another repository’s passing gate cannot approve it. The hook can keep working with the editor closed while the local backend is available.

This is local protection. `git --no-verify`, a changed hook or a different clone can bypass it; server protection is separate. Existing unrelated hooks are not overwritten.
