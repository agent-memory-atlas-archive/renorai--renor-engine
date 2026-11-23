# Contributing to Renor

Thanks for looking. This is a single-owner memory engine, so the bar is simple: a change should make it work better for the person running it, and it should come with a test.

## How your pull request lands

We export this repository from a private source repository. When we accept your
pull request, a maintainer re-applies your exact change there with you as the
commit author. Your change ships in the next `renor-engine` npm release. We then
close your pull request with a link to the released commit.

Expect a first reply within 24 hours. Accepted changes usually ship within a few
days.

## Set up

Renor needs **Node 22.16 or newer** (`.nvmrc` and `mise.toml` pin the tested Node 22): it stores through Node's built-in SQLite and loads sqlite-vec's prebuilt binary, so the install builds nothing. [Troubleshooting](docs/self-hosting.md#troubleshooting) has the fixes for an old Node or a missing sqlite-vec binary.

```bash
nvm use                 # or: mise use node@22
npm ci                  # without --omit=optional: sqlite-vec's binary is an optional dependency
npm run build
node scripts/smoke-self-hosted.mjs                  # ends with PASS
```

A copy without `.git` (a ZIP download) builds with `RENOR_BUILD_COMMIT=0000000 npm run build`; a git clone needs nothing.

## Test

```bash
npx tsc --noEmit
npx tsc -p tsconfig.public-eval.json --noEmit
npm test -- --maxWorkers=2
npm run eval:renor:hash -- --output .eval-runs/hash-smoke
```

These are the same steps as `.github/workflows/engine-public-ci.yml`; the CI badge on `main` should be green before you open a pull request. Tests use the offline `eval-hash` embedding stub. Do not add a test that needs a paid model, a downloaded model or the network.

## Good first issues

Browse the [open good first issues](https://github.com/renorai/renor-engine/issues?q=is:open+label:%22good+first+issue%22).
Comment on the issue before starting so others know you're working on it.

## Pull requests

- Open an issue first for anything larger than a bug fix, so we agree on the shape before you write it.
- Keep a pull request to one change. Say what it does, why, and which tests you ran.
- A bug fix needs a test that fails before the fix and passes after it.
- Say so in the description if the change loosens security (who can sign in, what a token can reach, what a tool returns) or changes retrieval results. Those get a closer review.
- Never commit credentials, real notes or personal paths. Test fixtures that look like secrets must be obviously synthetic and are allowlisted by exact path in `.gitleaks.toml`.
- Dependency updates are taken in the private repository this one is exported from, so Dependabot version-update pull requests here cannot land. There, `@modelcontextprotocol/sdk` minor and major bumps are held until `tests/mvp/schema-rejected-calls.test.ts` is reviewed against the new SDK.
- Please write issues, pull requests and reviews in English, so anyone can follow along; translated docs are welcome.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open a public issue for them.

## License

Inbound = outbound: by contributing you agree that your work is licensed under Apache-2.0, the same as the project ([LICENSE](LICENSE)). There is no CLA. Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`, which adds `Signed-off-by: Your Name <you@example.com>`); a pull request with an unsigned commit is not merged.
