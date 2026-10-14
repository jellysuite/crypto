# @jelly/crypto

Every lock in jellysuite. A thin, typed layer over libsodium: nothing here is home-made cryptography.

| File | What it is |
|---|---|
| `src/envelope.ts` | `seal` and `open`: XChaCha20-Poly1305 with a format byte, a type tag and associated data |
| `src/box.ts` | Sealed boxes, for giving a key to someone by their public key |
| `src/sign.ts` | Ed25519 signatures with a context string |
| `src/hash.ts` | Hashing and key derivation |
| `src/phrase.ts` | Recovery phrases and safety words |
| `src/encoding.ts` | base64url without padding, the only binary encoding on the wire |
| `src/sodium.ts` | `ready()`: wait for libsodium before anything else |

```sh
pnpm --filter @jelly/crypto test
```

## Rules

- All ciphertext in jellysuite goes through `seal`. The type tag says what a ciphertext is, and the associated
  data binds it to its item id and key version, so it can't be replayed somewhere else.
- It runs in the browser, Node, Tauri and React Native: no DOM, Node or Next imports.
- Dependencies must be MIT-compatible.

## Licence

MIT. See `LICENSE`.
