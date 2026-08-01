# Required GitHub repository settings

Repository files cannot enforce hosting settings. Before accepting contributions,
an administrator records screenshots/API evidence that `main` has:

- deletion and force-push disabled;
- pull requests required with at least two approvals for IC-1 changes;
- stale approvals dismissed and code-owner review required after owners exist;
- all conversations resolved;
- CI, formal models, CodeQL, and dependency review required as applicable;
- administrators subject to the same rules, with emergency bypass logged;
- secret scanning, push protection, private vulnerability reporting, Dependabot
  alerts, and dependency graph enabled;
- Actions restricted to trusted/pinned actions and read-only default token;
- release environments requiring independent approval and no untrusted PR access;
- immutable releases enabled when the GitHub plan supports them.

Do not add a placeholder `CODEOWNERS`: a nonexistent user/team creates a false
control. Add the file only after real technical, security, and assurance owners
are assigned, then make it a required review source.
