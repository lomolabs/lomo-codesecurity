# Small security review examples

Read each `vulnerable/` file beside its matching `fixed/` file. Each pair keeps
one ordinary task and changes the security boundary. The Python functions and
JavaScript exports are never called here. There is no server or install step.

**Scan these files; do not run, build or deploy them.** The password is synthetic
and has never been a service credential. The container and Kubernetes files
are source examples, not working applications. These examples are independently
authored under the repository's Apache-2.0 license.

| Task | What changes | Targeted lite finding in `vulnerable/` |
| --- | --- | --- |
| Account lookup | SQL interpolation → SQLite parameter binding | `sast.sql_string_format` · medium |
| Repository task | Caller-controlled shell command → two allowed tasks and fixed argv | `sast.python_shell_true` · high |
| JSON settings import | Code evaluation → JSON parsing | `sast.javascript_eval` · high |
| Service password | Hardcoded dummy → deployment-supplied environment value | `secret.generic_assignment` · high |
| Container user | No explicit user → numeric non-root user | `iac.docker_no_user` · medium |
| Pod permissions | Privileged/root/host mount → nonprivileged/non-root/no host mount | `iac.k8s_privileged` · critical; `iac.k8s_host_path` · high; `iac.k8s_root_allowed` · medium |

[expectations.json](expectations.json) records the exact targeted lite counts for
both sides. A host source-only regression checks those counts for all families
and each family separately, repeat identities, sanitized snippets and original
source coordinates without importing or executing any example. It is not native
scanner or release qualification.
The separate first-party OpenGrep pack should also flag the vulnerable Python
shell and JavaScript evaluation examples; its native execution must be checked
separately. All other engine findings remain visible.

For a product review, select and authorize this narrow directory using the
normal repository setup flow. In **Tools**, enable the relevant internal lite
family; these optional heuristics start disabled. Prepare the enabled tools,
scan, filter by the exact scanner/rule, and compare vulnerable and fixed paths.
Open the finding in Web detail and VS Code. Verify source navigation, snippets
and redaction through the actual product before treating the demo as accepted.
Disabling an engine or changing policy is not a way to turn incomplete evidence
into a passing gate.

The fixed files remove these specific patterns. They do not prove complete
application security: JSON still needs application validation, allowed tasks
still need an appropriate working directory, supplied credentials need lifecycle
management, and container examples need real image/workload review. A missing
Docker USER is a policy signal; it does not prove the inherited image user is
root. Lite rules are line heuristics, not general taint or dataflow analysis.

This is an additive review set. It does not change `examples/vulnerable-demo`,
the historical five-root inputs, the sealed fifteen-root workload or the
unchanged 531-file scanner regression.
