# GitHub: private repo, collaboration & CI/CD

The project is developed on GitHub (a **development/deployment** tool, not a
runtime dependency). Website auth (one shared account) and GitHub developer
identities are separate concerns.

## 1. Create the private repository

> Must be **private**, it may contain internal addresses and security notes.

With the `gh` CLI (authenticated):

```bash
gh repo create ad-command-center --private --source=. --remote=origin --push
```

If `ad-command-center` already exists, inspect its owner/contents first and pick a
safe alternative name rather than overwriting.

Without `gh`, create it in the GitHub UI as **Private**, then:

```bash
git remote add origin git@github.com:<you>/ad-command-center.git
git branch -M main
git push -u origin main
```

## 2. Collaborators (four developer identities)

`Settings → Collaborators → Add people` for each teammate's GitHub account. The
shared **website** login is unrelated to these GitHub identities.

## 3. Branch / PR workflow

GitHub Free private repos may not include branch protection, so adopt a convention:

- `main` is deployable; never push directly.
- Feature branches: `feat/<topic>`, `fix/<topic>`.
- Open a PR; CI (`.github/workflows/ci.yml`) runs lint + backend tests + frontend
  build + Docker build. At least one teammate reviews. Merge to `main`.
- If branch protection **is** available: require the `backend`, `frontend` and
  `docker-build` checks and one approving review.

## 4. CI/CD (secure deploy over Tailscale)

- **CI** runs on every push/PR: Ruff, pytest, `tsc` type-check, Vite build and
  Docker image builds. Default token is read-only.
- **Deploy** (`deploy.yml`) triggers only after CI succeeds on `main`, in the
  protected `production` environment. A GitHub-hosted runner joins your **private
  Tailscale tailnet** as an **ephemeral, tagged (`tag:ci`) node**, reaches **only**
  the VM's SSH port (enforced by your tailnet ACL), pulls, rebuilds, health-gates
  and rolls back on failure. **No public SSH rule and no permanent self-hosted
  runner.** Untrusted PR code never sees production secrets (deploy runs on `main`
  via the environment, not on PR branches).

### One-time setup

**A. On the VM, join the tailnet** (you run this; installing the daemon is a
persistence action reserved for the operator):
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-tags=tag:prod --ssh=false
tailscale ip -4          # note the 100.x.y.z address -> this is DEPLOY_HOST
```

**B. In the Tailscale admin console** (https://login.tailscale.com/admin):
1. **Access controls**, add tags and an ACL that lets CI reach only the VM's SSH:
   ```jsonc
   "tagOwners": { "tag:ci": ["autogroup:admin"], "tag:prod": ["autogroup:admin"] },
   "acls": [ { "action": "accept", "src": ["tag:ci"], "dst": ["tag:prod:22"] } ]
   ```
2. **Settings → OAuth clients**, create a client with the **`auth_keys`** scope and
   the tag **`tag:ci`**. Copy the client ID and secret.

**C. GitHub, set the `production` environment secrets** (Settings → Environments → production):

| Secret | Value |
|---|---|
| `TS_OAUTH_CLIENT_ID` | Tailscale OAuth client ID |
| `TS_OAUTH_SECRET` | Tailscale OAuth client secret |
| `DEPLOY_HOST` | the VM's **tailnet** IP (`100.x.y.z`) from step A |
| `DEPLOY_USER` | `lastpaksajiha` (in the `docker` group) |
| `DEPLOY_SSH_KEY` | the deploy user's private SSH key |

Then set the repository **variable** `DEPLOY_ENABLED=true`. Until it is set, the
Deploy workflow stays dormant (does not run or fail).

Already wired in this repo: the read-only `vm-pull` deploy key, the VM app dir as a
git checkout of `origin/main` (with `.env` preserved), `DEPLOY_USER`/`DEPLOY_SSH_KEY`
and the docker-group membership. You only need to add Tailscale (A–B) and the two
`TS_*` secrets, then point `DEPLOY_HOST` at the tailnet address.

Application secrets (`ADCC_SECRET_KEY`, the shared password) live in the server's
`.env` / admin CLI, **not** in GitHub.

## 6. Hardening notes

- Pin third-party Actions to commit SHAs for supply-chain safety (this repo pins to
  release tags for readability; replace with SHAs in a security-sensitive setup).
- Enable Dependabot / secret scanning in repo settings.
- Never commit `.env`, DBs, PCAPs, flags or keys, `.gitignore` already blocks them.
