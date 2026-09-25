# Demo app

A runnable web app wiring all three products — Singpass Login, Myinfo and
Myinfo Business (Corppass) — through the `singpass` and `web` packages. It
renders the validated id_token claims and the Myinfo person / entity data as
grouped sections, with the raw `/userinfo` JSON alongside.

Live (staging): https://rp-demo-1090410730433.asia-southeast1.run.app

For the smallest possible integration, see [`../minimal`](../minimal).

## Try it without onboarding

```sh
DEMO_MOCK=1 go run ./cmd/server   # http://localhost:8088
```

Mock mode starts fake Singpass and Corppass servers in-process
([`singpasstest`](../../singpasstest)), generates throwaway keys and registers
all three apps with them. Logging in shows a sign-in page listing test personas
(or Cancel, to see a declined login). No client IDs, keys or network access are
needed, and no real accounts or personal data are involved.

## Run locally against Singpass staging

You need a Singpass (and/or Corppass) **staging** client for each product you
want to try: a `client_id`, the public JWKS printed by `keygen` registered with
it, and the redirect URI `http://localhost:8088/<app>/callback` (apps: `login`,
`mi` for Myinfo, `mib` for Myinfo Business). From this directory:

```sh
cp .env.example .env      # set SINGPASS_LOGIN_CLIENT_ID / MYINFO_CLIENT_ID / MYINFO_BIZ_CLIENT_ID
go run ./cmd/keygen       # writes keys/<app>/{sig,enc}.pem and prints each public JWKS
set -a; . ./.env; set +a
go run ./cmd/server       # http://localhost:8088
```

Each app is enabled when its `*_CLIENT_ID` is set. The demo's `go.mod` points the library at the local tree with a `replace`
directive, so changes to the library are picked up without publishing. (A local
`go.work` covering both modules works too; it is gitignored.)

## Deployment

Every push to `main` runs [`deploy.yml`](../../.github/workflows/deploy.yml):
it tests both modules, builds [`Dockerfile`](Dockerfile)
(from the repo root, since the demo replaces the library with `../..`), and
deploys the image to Cloud Run (service `rp-demo`, project `singpass-demo-rp`,
`asia-southeast1`) at https://rp-demo-1090410730433.asia-southeast1.run.app. GitHub authenticates keylessly through Workload Identity
Federation, which only accepts this repo on `main`.

- **Config** — [`deploy/cloudrun.env.yaml`](deploy/cloudrun.env.yaml)
  is the service's complete non-secret environment; each deploy replaces the
  service's env vars with it.
- **Keys** — each private key is a Secret Manager secret
  (`singpass-demo-<app>-<sig|enc>`) mounted at `/secrets/<app>-<sig|enc>/key.pem`.
  Only the `singpass-demo-runtime` service account can read them; the deployer
  cannot. To rotate, add a new secret version and redeploy.
- **Single instance** — pending logins and app sessions are in memory, so the
  service runs with `--max-instances=1`; a scale-to-zero or redeploy logs
  everyone out.
- **Redirect URIs** — `<APP_BASE_URL>/<app>/callback` must be registered with
  each Singpass / Corppass client alongside the localhost ones. Singpass and
  Corppass reject redirect URIs containing "singpass", "corppass" or "myinfo"
  anywhere (host included), which is why the service is `rp-demo` and the demo's
  app slugs are `login`, `mi` (Myinfo) and `mib` (Myinfo Business).

The container reads Cloud Run's `PORT` (`APP_ADDR` still wins if set), logs
JSON for Cloud Logging when `LOG_FORMAT=json` (set in the image), and shuts down
gracefully on `SIGTERM`.
