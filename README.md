# github-core-clone-01-entry

A GitHub-compatible git forge, built for the
[github-core-clone-01](https://make.fun/bounty/github-core-clone-01) bounty.
Node 22 standard library only — no dependencies, no git binary, no install
step. Everything lives in memory; the entry holds no state of its own across
runs, so every check seeds its own fixtures through the API.

## Run

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:8080 MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

The process binds an ephemeral port, registers it with the env
(`POST $MAKEFUN_ENV_URL/register`), polls `GET $MAKEFUN_ENV_URL/done` until
the trial is over, then exits 0. It never binds 8080.

## Surface

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok": true}` |
| `GET /api/v3/` | API root, `X-OAuth-Scopes: repo, read:org` |
| `GET /api/v3/meta` | `{"installed_version": ...}` |
| `GET /api/v3/user` | The token owner's login |
| `/api/v3/...` | REST v3: repositories, branches, commits, contents, labels, issues, comments, pull requests, files, squash merges |
| `POST /api/graphql` | GraphQL v4: viewer, repository, issue/pull-request reads, create/close/merge mutations, `__type` introspection, `node(id:)`, batched operations, cursor pagination |
| `POST /mcp` | MCP over streamable HTTP: `server/discover` (2026-07-28) and the `initialize` handshake era, `tools/list`, `tools/call` |
| `/{owner}/{repo}.git/...` | git smart HTTP: protocol v2 (fetch, ls-refs, shallow/deepen) and v0, plus receive-pack with per-ref report-status |

## Notes

- Auth: every API call carries `Authorization: Bearer $MAKEFUN_SHOP_TOKEN`.
  A missing or wrong token is 401. A repository belongs to the login the
  token names (`adaiversen`, fixed by the contest's seeded scenario), so the
  same repository name under another owner is 404, never 403.
- Git objects are real: packfiles are written and read by hand
  (loose objects, pkt-line framing, side-band-64k), pushes are fast-forward
  only with per-ref `ng <ref> non-fast-forward` refusals, and fetches honour
  haves, shallow boundaries and deepen.
- Contents writes and squash merges synthesize real commits (fixed identity
  and timestamp, so a run's bytes are deterministic) on the same object
  store the git protocol reads from.
- The token owner's login is fixed by the contest's seeded scenario
  (seed `0x6a09e667f3bcc909`); the entry does not invent logins.
