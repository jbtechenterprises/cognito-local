# P0: Bump the pinned cognito-local docker image — infra investigation

**Date:** 2026-07-03
**Fork HEAD:** `v5.3.0-7-ge3086e7` (commit `e3086e7`, branch `m2m-oauth2-support`)
**Currently pinned test image:** `cognito-local:5.1.0-m2m-fix`

## TL;DR

The fork now sits on top of upstream **v5.3.0** (see `CHANGELOG.md`), but every consumer
still pins **`cognito-local:5.1.0-m2m-fix`** — a tag named for the upstream *5.1.0* era.
The tag is **stale/misleading**: it does not reflect the code the fork actually builds.
There are **exactly three docker-compose pins** (1 in boostideal, 2 in deploy) plus one
Taskfile variable that produces the tag, plus a handful of doc mentions.

The image is **local-build only** — it is not published to any registry. The publish
CI/GHCR workflow was intentionally removed (commit `e3086e7`,
"chore(ci): use local docker image name and drop GHCR publish workflow"). Consumers
rely on the developer having run `task docker:build` in this repo first.

## 1. How the fork builds & tags its image (cognito-local repo)

### `Taskfile.yml` — source of truth for the tag

`/Users/jon/code/jbtechenterprises/cognito-local/Taskfile.yml`

```yaml
1  version: "3"
2
3  vars:
4    IMAGE: cognito-local
5    TAG: 5.1.0-m2m-fix
6
7  tasks:
8    docker:build:
9      desc: Build the cognito-local docker image tagged {{.IMAGE}}:{{.TAG}}
10     cmds:
11       - docker build -t {{.IMAGE}}:{{.TAG}} .
```

- Line 4: `IMAGE: cognito-local`
- Line 5: `TAG: 5.1.0-m2m-fix`  ← the single place the tag is minted
- Lines 8-11: `docker:build` runs `docker build -t cognito-local:5.1.0-m2m-fix .`

Result: `task docker:build` produces the local image **`cognito-local:5.1.0-m2m-fix`**.

### `Dockerfile`

`/Users/jon/code/jbtechenterprises/cognito-local/Dockerfile`

- `FROM node:22.13.1-alpine` (builder + runtime), esbuild bundle of `src/bin/start.ts`
- `EXPOSE 9229`, `ENV PORT 9229`, `ENTRYPOINT ["node", "/app/start.js"]`
- No version label is baked in; the version identity lives only in the image *tag*.

### Version identity

- `package.json` line 3: `"version": "0.0.0-development"` — a placeholder. This repo uses
  **semantic-release**; the real version is derived from git tags, not package.json.
- Latest git tag / `git describe`: **`v5.3.0-7-ge3086e7`**.
- `CHANGELOG.md` top entry: **`5.3.0`** (2026-05-21, oauth2 auth-code + PKCE). The `+7`
  commits on top add the M2M / `client_credentials` work.
- So the fork's true base is **upstream 5.3.0**, while the pinned tag still says **5.1.0**.

### Not used by the fork

- `scripts/dockerBuildPush.sh` is the **upstream** multi-arch publish script
  (`--tag jagregory/cognito-local:...  --push`). It targets Docker Hub `jagregory/*`
  and is **not** part of the fork's local build flow.
- `.github/workflows/main.yml` contains **no** image build/tag/publish steps (grep for
  `cognito-local|docker build|IMAGE|TAG|ghcr` returns nothing). Publish was dropped.

## 2. The three docker-compose pins of `cognito-local:5.1.0-m2m-fix`

### (a) boostideal — integration tests

`/Users/jon/code/solutionsinabox/boostideal/dev/docker/docker-compose.integration_tests.yaml`

```yaml
209  # Cognito Local for AWS Cognito emulation (user pools, app clients, authentication)
210  # Using custom fork with M2M/client_credentials support (PR #376 + scope fix).
...
212  it-cognito-local:
213      image: cognito-local:5.1.0-m2m-fix
214      container_name: it-cognito-local
...
219        - "127.0.0.1:9230:9229"
...
228        - ./cognito-local-config.json:/app/.cognito/config.json
...
233      healthcheck:
234        test: ["CMD", "wget", "-q", "--spider", "http://localhost:9229/health"]
```

- **Pin:** line 213 `image: cognito-local:5.1.0-m2m-fix`
- Service `it-cognito-local`, container `it-cognito-local`
- Port: host `127.0.0.1:9230` → container `9229`
- Env: `CODE: "123456"`, `DEBUG: "1"`
- Healthcheck: `wget -q --spider http://localhost:9229/health`

### (b) deploy — localprod core

`/Users/jon/code/solutionsinabox/deploy-aws-production-enablement/dev/boostideal/local/docker-compose.core.yaml`

```yaml
100  cognito-local:
101      image: cognito-local:5.1.0-m2m-fix
102      container_name: cognito-local
103      hostname: cognito-local
...
111        - "9229:9229"
...
114        - ${BOOSTIDEAL_REPO_PATH:?...}/dev/cognito-local-seed/db:/app/.cognito/db
115        - ./cognito-local-config.json:/app/.cognito/config.json
116      healthcheck:
117        <<: *healthcheck-defaults
118        test: ["CMD", "wget", "-q", "--spider", "http://127.0.0.1:9229/health"]
```

- **Pin:** line 101 `image: cognito-local:5.1.0-m2m-fix`
- Service `cognito-local`, container `cognito-local`
- Port: `9229:9229`
- Mounts seed DB from `${BOOSTIDEAL_REPO_PATH}/dev/cognito-local-seed/db`
- Header comment (lines 92-96) explicitly says the image is a **LOCAL build tag**, NOT
  published, and to run `task docker:build` in the fork first.

### (c) deploy — localprod E2E

`/Users/jon/code/solutionsinabox/deploy-aws-production-enablement/dev/boostideal/local/docker-compose.e2e.yaml`

```yaml
101  cognito-local:
102      image: cognito-local:5.1.0-m2m-fix
103      container_name: e2e-cognito-local
104      hostname: cognito-local
...
112        - "9329:9229"
...
115        - ${BOOSTIDEAL_REPO_PATH:?...}/dev/cognito-local-seed/db:/app/.cognito/db
116        - ./cognito-local-config.json:/app/.cognito/config.json
117      healthcheck:
118        <<: *healthcheck-defaults
119        test: ["CMD", "wget", "-q", "--spider", "http://127.0.0.1:9229/health"]
```

- **Pin:** line 102 `image: cognito-local:5.1.0-m2m-fix`
- Service `cognito-local`, container `e2e-cognito-local` (e2e- prefix convention)
- Port: host `9329` → container `9229` (offset so it can co-exist with core's 9229)
- Note comment line 96 is stale too: "Built from: /tmp/cognito-local".

## 3. Other references to the pinned tag (docs — not functional pins)

These do not build/run the image but should be updated for consistency:

- `/Users/jon/code/jbtechenterprises/cognito-local/Taskfile.yml:5` — the TAG var (source of truth; #1 above)
- `/Users/jon/code/jbtechenterprises/cognito-local/docs/requirements/boostideal-parity-requirements.md:10` and `:22`
- `/Users/jon/code/solutionsinabox/deploy-aws-production-enablement/docs/onboarding/00-lay-of-the-land.md:62`
- `/Users/jon/code/solutionsinabox/deploy-aws-production-enablement/docs/onboarding/10-run-localprod.md:41` and `:81`

No `.env` files, Makefiles, or CI workflows reference the tag. Boostideal's `Taskfile.yml`
references cognito **containers** (`it-cognito-local`) for logs/health/init but never the
image tag.

## 4. How the image is consumed in integration/E2E tests

| Consumer | File | Service | Container | Host port → 9229 | Healthcheck |
|---|---|---|---|---|---|
| boostideal IT | docker-compose.integration_tests.yaml | `it-cognito-local` | `it-cognito-local` | `127.0.0.1:9230` | `wget http://localhost:9229/health` |
| deploy localprod core | docker-compose.core.yaml | `cognito-local` | `cognito-local` | `9229` | `wget http://127.0.0.1:9229/health` |
| deploy localprod e2e | docker-compose.e2e.yaml | `cognito-local` | `e2e-cognito-local` | `9329` | `wget http://127.0.0.1:9229/health` |

- Container always listens on **9229** (from the Dockerfile), health at `/health`.
- boostideal drives the stack via `Taskfile.yml`:
  - `infra:integration:up` → `docker compose -f dev/docker/docker-compose.integration_tests.yaml up -d`
  - `infra:integration:cognito:init` → `bash ./dev/docker/init-cognito-local.sh`
  - `infra:integration:cognito:logs` → `docker logs it-cognito-local`
  - `infra:integration:cognito:status` → health probe on `http://localhost:9230/health`
- deploy stacks mount deterministic seed data (`dev/cognito-local-seed/db`) and a
  `cognito-local-config.json`; init handled by `deploy/scripts/init-cognito-local.sh`.

## 5. Proposed new tag

Pick a tag that reflects the fork's real base so it stops lying about 5.1.0. Recommended:

- **`cognito-local:5.3.0-m2m`** — matches upstream base v5.3.0 + the M2M feature suffix.
  (Alternative, if we want to keep the `-fix` suffix parity with the old name:
  `cognito-local:5.3.0-m2m-fix`.)

The bump is small and mechanical:
1. `cognito-local/Taskfile.yml:5` — `TAG: 5.3.0-m2m` (the mint point)
2. `boostideal/.../docker-compose.integration_tests.yaml:213`
3. `deploy/.../docker-compose.core.yaml:101`
4. `deploy/.../docker-compose.e2e.yaml:102`
5. Doc mentions listed in section 3.

All five (well, the 4 functional + docs) must move together in lockstep, because the image
is local-build-only: if the Taskfile tag and the compose pins diverge, `docker compose up`
fails with "image not found" (there is no registry to pull a fallback from).

## Open questions

1. **Tag naming convention** — `5.3.0-m2m` vs `5.3.0-m2m-fix` vs a git-SHA/`git describe`
   based tag (`5.3.0-7-ge3086e7`)? SHA-based is immutable but noisy for a local dev image.
2. **Should this image be published** to a registry (ECR/GHCR) so CI and teammates don't
   each have to `task docker:build`? Publish was deliberately dropped in `e3086e7`; is that
   still the intended posture, or does P0 want a published, pull-able image?
3. **Cross-repo coordination** — the pins live in three repos on possibly different
   branches. Do all three land in one coordinated PR set, or is there a rollout order
   (fork Taskfile first, then consumers)?
4. **Stale comments** — `docker-compose.e2e.yaml:96` says "Built from: /tmp/cognito-local"
   which is wrong (it's this fork). Worth fixing while touching these files.
5. Confirm nothing outside these three repos consumes the tag (e.g. any developer-local
   scripts or a separate CI runner config not in-tree).
