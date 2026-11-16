# github-core-clone

A single-process, GitHub-compatible git forge written from scratch in one
TypeScript file (`main.ts`), using only the Node 22 standard library — no
dependencies, no git binary, no outside services. It speaks the surfaces a
real `git` client, `gh`, and the GitHub MCP server speak:

![github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)
![rank](https://make.fun/badge/github-core-clone-01/donglin3800/github-core-clone-01/rank.svg)
![reward](https://make.fun/badge/github-core-clone-01/donglin3800/github-core-clone-01/reward.svg)

Built for the [github-core-clone-01 bounty](https://make.fun/bounty/github-core-clone-01)
on [make.fun](https://make.fun).

## What it implements

- **Lifecycle** — binds an ephemeral port, registers it with
  `$MAKEFUN_ENV_URL/register`, polls `$MAKEFUN_ENV_URL/done` and exits 0 when
  the trial is done. `GET /healthz` answers `200 {"ok": true}` with no auth.
  With no `MAKEFUN_ENV_URL` set it simply serves forever (local test mode).
- **Git smart HTTP** (`/{owner}/{repo}.git`) — upload-pack protocol v2
  (`version 2` advertisement, `ls-refs` with server-side ref-prefix filtering,
  peel and symrefs, `fetch` with depth/shallow/unshallow handling) and v0
  fallback, plus receive-pack v0 with `report-status`, `side-band-64k` and
  `delete-refs`. Packfiles are read and written by hand (pkt-lines, zlib,
  SHA-1 object ids, OFS/REF delta resolution on read, plain objects on
  write). Pushes are fast-forward only: a non-fast-forward ref is refused
  with `ng <ref> non-fast-forward` while the other refs in the same command
  list still apply. A push cannot invent a repository.
- **REST v3** (`/api/v3`) — repositories (create/read/patch/delete, paginated
  lists with `Link: rel="next"`), branches, git refs, commits, contents
  (create/update/delete as real git commits, 409 on a stale sha), labels,
  issues (with comments), and pull requests (files diff, squash merge,
  three-way conflict detection returning 405). Every reply is
  `application/json` with a non-empty `X-GitHub-Request-Id`; bearer-token
  auth is required (401 without it) and a repo under another owner is 404,
  never 403.
- **GraphQL** (`POST /api/graphql`) — a small executor for the documents `gh`
  sends: `viewer`, `repository` (with `issues`/`pullRequests` connections,
  cursor pagination, `orderBy`, `states` filtering), `issue`/`pullRequest`
  reads, `node(id:)` with inline fragments, the `createIssue` / `closeIssue`
  / `createPullRequest` / `mergePullRequest` / `addComment` mutations, batch
  requests answered in order, `__type` introspection, and opaque stable
  global ids. Unknown fields answer HTTP 200 with an `errors` array naming
  the field; unknown repositories answer `data.repository = null`.
- **MCP** (`POST /mcp`) — JSON-RPC 2.0 Streamable HTTP speaking revision
  `2026-07-28` via `server/discover` (with a legacy `initialize` handshake
  as well): `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`, all acting on the same store
  as REST. Unknown tools answer `-32602`, missing arguments `-32602`,
  malformed JSON answers HTTP 400 with `-32700`, and unauthenticated calls
  answer 401. `tools/list` is byte-identical across calls.

## Properties

- **In-memory, one process** — no persistence is needed; each trial starts
  fresh.
- **Deterministic** — no wall clock and no randomness anywhere in stored
  state or responses (fixed epoch plus per-repo counters for commit
  timestamps, sequential counters and content hashes for ids), so a replay
  leaves byte-identical state.
- **Fast** — O(1) maps everywhere, cached git responses (advertisement,
  ls-refs, fetch packs) invalidated on any object/ref change, and a cached
  serialization for the hot single-issue read path.

## Run it

```sh
MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

With `MAKEFUN_ENV_URL` set it joins a trial; without it, it serves on an
ephemeral loopback port (see the `listening on ...` line) for local testing
against the kit's `sdk/run.ts`.

## Layout

- `main.ts` — the whole forge (single file, erasable TypeScript only).
- `package.json` — `{"type": "module"}` so Node runs `main.ts` directly.
- `LICENSE` — MIT.
- `.makefun/owner.json` — payout wallet for the bounty.

## License

MIT — see [LICENSE](LICENSE).
