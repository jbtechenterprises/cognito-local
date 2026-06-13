# cognito-local

## localindex workspace — ALWAYS pass `--workspace cognito-local`

This repository is indexed by the **`cognito-local`** localindex workspace. A single
system daemon serves every workspace, so the CLI **requires** an explicit
workspace. Always run:

```bash
localindex --workspace cognito-local query "<what you need>"
localindex --workspace cognito-local status
```

Never omit `--workspace`. If you do, the CLI refuses and names the workspace your
directory belongs to — re-run with that name. Follow the global `localindex`
skill's investigate-before-reading workflow (query before any Read/Grep/Glob).
