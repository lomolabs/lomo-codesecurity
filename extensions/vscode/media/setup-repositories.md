# A workspace can hold many repositories

```text
workspace/                 ← remains your open folder
  service-api/             ← one selected repository
  web-client/              ← another selected repository
  shared-library/          ← select when you need it
```

Choose the children you want to manage. The parent does not become a scanner root. Review the exact source paths before applying the host authorization command.

Each child keeps its own project, scan and gate. Adding it to VS Code, selecting it here, authorizing scanner access and submitting a scan are separate actions.

Removing a selection does not delete projects or remove push protection.

When adding a folder turns this window into an untitled workspace, your selected
children stay associated with their projects. If VS Code cannot identify the
original window, use **Restore selections** or **Choose repositories**. Neither
action grants scanner access or enables protection.
