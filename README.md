# jellysuite crypto

The encryption at the heart of [jellysuite](https://jellysuite.com): everything your device does to lock your
work before it leaves, and to decide who else may open it. The server only ever stores what these packages
produce.

| Package | What it is |
|---|---|
| [`packages/crypto`](packages/crypto) | Every lock: a thin, typed layer over libsodium. Nothing here is home-made cryptography |
| [`packages/core`](packages/core) | The key hierarchy and the sharing rules: which key unlocks which, who can unwrap what, and why |

```sh
pnpm install
pnpm test
pnpm typecheck
```

Node 24 and pnpm. Both packages run in the browser, Node, Tauri and React Native.

## Where this comes from

jellysuite is developed in a private repository. This one is a copy of these two packages, updated
automatically whenever they change there: each commit is "Sync with jellysuite `<commit>`". Issues and pull
requests are welcome; accepted changes are made in the private repository and arrive here with the next sync.

Found a security problem? Please don't open an issue: see https://jellysuite.com/.well-known/security.txt.

## Licence

MIT. See `LICENSE`.
