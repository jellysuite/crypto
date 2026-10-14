import sodiumModule from "libsodium-wrappers-sumo";

type Sodium = typeof sodiumModule;

let loaded: Sodium | null = null;

export async function ready(): Promise<void> {
  await sodiumModule.ready;
  loaded = sodiumModule;
}

/** The initialized libsodium instance. `ready()` must have resolved first. */
export function sodium(): Sodium {
  if (!loaded) throw new Error("@jelly/crypto: call ready() before using crypto functions");
  return loaded;
}
