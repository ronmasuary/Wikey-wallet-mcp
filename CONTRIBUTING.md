# Contributing

Source of truth is **GitLab**: https://gitlab.com/bit2safe/wikey-wallet-mcp

**GitHub is a read-only push mirror.** Issues and merge requests go through
GitLab — contact the Wikey team for access.

## Git flow

- Branch off `origin/beta`; merge target is `origin/beta`. `main` is updated
  separately via a `beta → main` merge.
- Conventional-commit prefixes: `fix/`, `feat/`, `chore/`, etc.
- Open the merge request against `beta` on GitLab.

## Before you push

```bash
npm install
npm run build
npm test
```

CI (`.github/workflows/ci.yml`) runs install → build → test on PRs and pushes to
`beta`/`main`.

## Project conventions

- Greenfield ESM TypeScript, Node 22+, `strict` + `noUncheckedIndexedAccess`.
- Keep the security invariants in `CLAUDE.md` intact; they have tests
  (`sealing.test.ts`, `configLock.test.ts`, `snapshotCache.test.ts`, …).
- The skill at `Wikey-Wallet-Skill` is **frozen reference** — port from it, do
  not import or modify it.
