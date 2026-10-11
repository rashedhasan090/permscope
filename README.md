# permscope

Infer the `GITHUB_TOKEN` permissions each GitHub Actions job actually needs, then diff them against what the workflow grants.

## What's novel

Most workflow linters only tell you "add a `permissions:` block". permscope goes further. It reads every job's `uses:` actions and `run:` scripts, infers evidence-backed scopes (for example `git push` needs `contents: write`, `gh pr comment` needs `pull-requests: write`, `docker push ghcr.io/...` needs `packages: write`, cloud OIDC login actions need `id-token: write`), and reports three things per job:

- **excess** scopes granted without evidence (attack surface if a step is compromised)
- **missing** scopes the job evidently needs (it will fail with 403 at runtime)
- **no-permissions / write-all** jobs running on broad defaults

It also prints a ready-to-paste least-privilege `permissions:` block per job. Offline, stdlib-only Python, no YAML dependency.

## Install

```bash
pip install git+https://github.com/rashedhasan090/permscope
# or run from a checkout
python3 -m permscope .
```

## Run

```bash
permscope .                      # scans .github/workflows under the path
permscope --json .github/workflows/release.yml
permscope --fail-on medium .     # nonzero exit for CI gating
```

## Demo

```text
$ permscope examples
examples/.github/workflows/release.yml:10 job 'publish' (perms from job)
  [high] contents: needs write but granted read (job will likely fail)
  [medium] issues: granted write but only none is evidenced
  [high] packages: needs write but granted none (job will likely fail)
  suggested:
    permissions:
      contents: write
      packages: write
```

## Limits

Inference is rule-based: unknown third-party actions contribute no evidence, so review suggestions for jobs that use them. Rules live in `ACTION_RULES` and `RUN_RULES` in `permscope/cli.py`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

MIT
