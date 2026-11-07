# GitHub: private repo, collaboration & CI/CD

The project is developed on GitHub (a **development/deployment** tool, not a
runtime dependency). Website auth (one shared account) and GitHub developer
identities are separate concerns.

## 1. Create the private repository

> Must be **private** — it may contain internal addresses and security notes.

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
- If branch protection **is** available: require the `backend`, `frontend`, and
  `docker-build` checks and one approving review.

## 4. CI/CD

- **CI** runs on every push/PR: Ruff, pytest (40 tests), `tsc` type-check, Vite
  build, and Docker image builds. Default token is read-only (`permissions: contents: read`).
- **Deploy** (`deploy.yml`) triggers only after CI succeeds on `main`, runs in the
  `production` GitHub **Environment**, SSHes to the VPS, pulls, rebuilds, health-gates,
  and rolls back on failure. Untrusted PR code never sees production secrets because
  deploy runs on `main` via the protected environment, not on PR branches.

## 5. Required secrets

Set under **Settings → Environments → production**:

| Secret | Purpose |
|---|---|
| `DEPLOY_HOST` | VPS hostname/IP |
| `DEPLOY_USER` | SSH user (member of `docker` group) |
| `DEPLOY_SSH_KEY` | Private key for that user (deploy-only, least privilege) |

On the VPS: clone to `/opt/adcc-command-center`, create `.env`, and ensure the
deploy user can run `docker compose`. Application secrets (`ADCC_SECRET_KEY`, the
shared password) live in the server's `.env` / admin CLI — **not** in GitHub.

## 6. Hardening notes

- Pin third-party Actions to commit SHAs for supply-chain safety (this repo pins to
  release tags for readability; replace with SHAs in a security-sensitive setup).
- Enable Dependabot / secret scanning in repo settings.
- Never commit `.env`, DBs, PCAPs, flags, or keys — `.gitignore` already blocks them.
