# Prepare once, scan each repository

In the dashboard, open **Tools** and choose **Prepare all scanners**. Wait for readiness, then use **Scan Workspace Folders…** to review and submit the selected repositories.

Read each result separately:

- **Complete:** the requested tools produced usable coverage.
- **Partial or failed:** review the cause and retry after fixing it.
- **Cancelled:** no passing gate is inferred.

Expired bundled data needs refreshed reviewed source and a rebuild, followed by preparation. Downloading the same expired data does not renew it.

A complete scan can still fail its gate because of findings. That is a useful result.
