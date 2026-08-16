# Vendored dependencies

`miijs-3.1.0-ltd-workspace.tgz` is a whole-package snapshot of the audited,
LTD-capable MiiJS worktree based on commit
`9734717986f6954c90692c29d5da93985bd72d4d`. The archive includes coordinated
LTD changes that are not yet published in that commit. The source workspace identifies
`https://github.com/Stewared/MiiJS.git` as its upstream repository. The public
`miijs@3.1.0` package does not yet contain the coordinated LTD container and
conversion implementation, so InfiniMii pins this archive rather than relying
on a sibling checkout or copying individual codec files.

Archive byte length: `9564329`.

Archive SHA-256: `ccc6a4f1b1fa3ab02db27934ba42bfb1d65801e45cd03295a12f36b0a95629b1`.

Verify it before install or deployment:

```powershell
(Get-FileHash vendor/miijs-3.1.0-ltd-workspace.tgz -Algorithm SHA256).Hash
```

```bash
sha256sum vendor/miijs-3.1.0-ltd-workspace.tgz
```

Replace this archive with an exact released MiiJS version or commit as soon as
the LTD changes are published. Do not replace it with registry `3.1.0`: that
version cannot decode, encode, or convert LTD files.
