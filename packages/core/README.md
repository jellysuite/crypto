# @jelly/core

The key hierarchy and the sharing rules that every app runs on your device: which key unlocks which, who can
unwrap what, and why.

| File | What it is |
|---|---|
| `src/account.ts`, `src/recovery.ts` | Account keys, and getting them back with the recovery key |
| `src/nodes.ts` | Item keys, and the link from a folder's key to its children's |
| `src/grants.ts` | Shares: a key sealed to a person, and the signed statements about who may hold it |
| `src/links.ts` | Share links, with or without a password |
| `src/resolver.ts` | Finds a route from the keys you hold to the key you need |
| `src/pins.ts` | Remembering a person's key, so a changed key is noticed |
| `src/teams.ts` | Team and group keys |
| `src/api.ts` | The wire types shared with the server. Types only |

```sh
pnpm --filter @jelly/core test
```

Depends on `@jelly/crypto` only. It runs in the browser, Node, Tauri and React Native: no DOM, Node or Next imports. Dependencies must be MIT-compatible.

The design is in `docs/superpowers/specs/2026-10-06-foundation-design.md`.

## Licence

MIT. See `LICENSE`.
