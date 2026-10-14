import type { Bytes, KeyPair } from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { type Grant, openGrant, verifyGrant } from "./grants.ts";
import { type ChildLink, unwrapChildKey } from "./nodes.ts";
import { type GroupGrant, openGroupGrant, verifyGroupGrant } from "./teams.ts";
import type { B64, PublicIdentity, Role } from "./wire.ts";

export type TreeNode = {
  id: string;
  parentId: string | null;
  kind: string;
  keyVersion: number;
  meta: B64;
  needsRotation: boolean;
  /** Doesn't inherit access from its parent: its key comes only from its own grants. */
  restricted: boolean;
  role: Role;
  /** Server timestamps (ISO): visible to the server anyway, used for sorting. */
  createdAt: string;
  updatedAt: string;
};

const ref = (id: string, version: number) => `${id}:${version}`;

/**
 * How the resolver reached a key: through `link`, a child link under the key of `parentId` (bound by the link's
 * associated data; kept so a caller can check later that the parent key it holds really wraps this key), a grant
 * to this account (from `grantorId`, whose signature on it verified), a group grant, or handed in with `setKey`.
 */
export type KeyVia =
  | { kind: "link"; parentId: string; link: ChildLink }
  | { kind: "grant"; grantorId: string }
  | { kind: "group"; groupId: string; grantorId: string }
  | { kind: "set" };

/**
 * Finds node keys: via the parent's key and a child link when the parent is reachable, else a verified
 * grant to the current account, else a verified group grant whose group key is known. Links win so a
 * server can't swap in its own key for a folder the user already reaches through its parent. Grants
 * that fail `trustGrant`/`trustGroupGrant` or signature checks are never opened; their nodes land in
 * `unverified`.
 */
export class KeyResolver {
  readonly unverified = new Set<string>();
  private readonly grants = new Map<string, Grant>();
  private readonly groupGrants = new Map<string, GroupGrant[]>();
  private readonly groupKeys = new Map<string, KeyPair>();
  private readonly links = new Map<string, ChildLink>();
  private readonly keys = new Map<string, Bytes>();
  private readonly vias = new Map<string, KeyVia>();
  private readonly account?: UnlockedAccount;
  private readonly identities: (userId: string, nodeId: string) => PublicIdentity | undefined;
  private readonly trustGrant: (g: Grant) => boolean;
  private readonly trustGroupGrant: (g: GroupGrant) => boolean;

  constructor(opts: {
    account?: UnlockedAccount;
    /** The grantor's identity for a grant on `nodeId` (which may decide whom to trust there). */
    identities: (userId: string, nodeId: string) => PublicIdentity | undefined;
    /** Extra policy on which grants may be used at all (e.g. only self-grants on your own root). */
    trustGrant?: (g: Grant) => boolean;
    /** Same, for group grants: without a policy any registered user's signature on a group grant is enough. */
    trustGroupGrant?: (g: GroupGrant) => boolean;
  }) {
    this.account = opts.account;
    this.identities = opts.identities;
    this.trustGrant = opts.trustGrant ?? (() => true);
    this.trustGroupGrant = opts.trustGroupGrant ?? (() => true);
  }

  addGrant(g: Grant): void {
    if (g.granteeId === this.account?.userId) this.grants.set(ref(g.nodeId, g.keyVersion), g);
  }

  addGroupGrant(g: GroupGrant): void {
    const r = ref(g.nodeId, g.keyVersion);
    const list = this.groupGrants.get(r) ?? [];
    list.push(g);
    this.groupGrants.set(r, list);
  }

  setGroupKey(groupId: string, version: number, keyPair: KeyPair): void {
    this.groupKeys.set(ref(groupId, version), keyPair);
  }

  addChildLink(l: ChildLink): void {
    this.links.set(ref(l.childId, l.childVersion), l);
  }

  setKey(nodeId: string, keyVersion: number, key: Bytes): void {
    this.keys.set(ref(nodeId, keyVersion), key);
    this.vias.set(ref(nodeId, keyVersion), { kind: "set" });
  }

  /** How the key for this node version was reached, once `keyFor` found it (undefined otherwise). */
  via(nodeId: string, keyVersion: number): KeyVia | undefined {
    return this.vias.get(ref(nodeId, keyVersion));
  }

  /**
   * The key the grant to this account opens for this node version, when there is one that verifies: the other
   * way to a key the resolver reached through a link. Nothing changes until `take`.
   */
  grantRoute(nodeId: string, keyVersion: number): { key: Bytes; via: KeyVia } | null {
    return this.fromGrant(ref(nodeId, keyVersion));
  }

  /** Makes `found` the way this node version is reached from here on (what hangs under it unwraps under its key). */
  take(nodeId: string, keyVersion: number, found: { key: Bytes; via: KeyVia }): void {
    this.keys.set(ref(nodeId, keyVersion), found.key);
    this.vias.set(ref(nodeId, keyVersion), found.via);
    this.unverified.delete(nodeId);
  }

  keyFor(nodeId: string, keyVersion: number): Bytes | null {
    return this.resolve(nodeId, keyVersion, new Set());
  }

  private resolve(nodeId: string, keyVersion: number, visiting: Set<string>): Bytes | null {
    const r = ref(nodeId, keyVersion);
    const cached = this.keys.get(r);
    if (cached) return cached;
    if (visiting.has(r)) return null;
    visiting.add(r);

    const found = this.fromLink(r, visiting) ?? this.fromGrant(r) ?? this.fromGroupGrant(r);
    const key = found?.key ?? null;
    if (found) {
      this.keys.set(r, found.key);
      this.vias.set(r, found.via);
      this.unverified.delete(nodeId);
    }
    return key;
  }

  private fromGrant(r: string): { key: Bytes; via: KeyVia } | null {
    const g = this.grants.get(r);
    if (!g || !this.account) return null;
    if (!this.trustGrant(g)) {
      this.unverified.add(g.nodeId);
      return null;
    }
    const grantor = this.identities(g.grantorId, g.nodeId);
    if (!grantor || !verifyGrant(g, grantor.signPub)) {
      this.unverified.add(g.nodeId);
      return null;
    }
    try {
      return { key: openGrant(this.account, g), via: { kind: "grant", grantorId: g.grantorId } };
    } catch {
      this.unverified.add(g.nodeId);
      return null;
    }
  }

  private fromGroupGrant(r: string): { key: Bytes; via: KeyVia } | null {
    for (const g of this.groupGrants.get(r) ?? []) {
      if (ref(g.nodeId, g.keyVersion) !== r) continue;
      if (!this.trustGroupGrant(g)) {
        this.unverified.add(g.nodeId);
        continue;
      }
      const groupKey = this.groupKeys.get(ref(g.groupId, g.groupVersion));
      if (!groupKey) continue;
      const grantor = this.identities(g.grantorId, g.nodeId);
      if (!grantor || !verifyGroupGrant(g, grantor.signPub)) {
        this.unverified.add(g.nodeId);
        continue;
      }
      try {
        return { key: openGroupGrant(groupKey, g), via: { kind: "group", groupId: g.groupId, grantorId: g.grantorId } };
      } catch {
        this.unverified.add(g.nodeId);
      }
    }
    return null;
  }

  private fromLink(r: string, visiting: Set<string>): { key: Bytes; via: KeyVia } | null {
    const l = this.links.get(r);
    if (!l) return null;
    const parentKey = this.resolve(l.parentId, l.parentVersion, visiting);
    if (!parentKey) return null;
    try {
      return {
        key: unwrapChildKey(parentKey, l),
        via: { kind: "link", parentId: l.parentId, link: l },
      };
    } catch {
      return null;
    }
  }
}
