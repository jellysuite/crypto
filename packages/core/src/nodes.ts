import {
  type Bytes,
  fromBase64Url,
  generateKey,
  open,
  openJson,
  seal,
  sealJson,
  toBase64Url,
  utf8,
} from "@jelly/crypto";
import { TAG } from "./tags.ts";
import type { B64 } from "./wire.ts";

export type NodeMeta = { title: string; [key: string]: unknown };

export const newNodeKey = (): Bytes => generateKey();

export const nodeAd = (nodeId: string, keyVersion: number): Bytes => utf8(`${nodeId}:${keyVersion}`);

export const encryptNodeMeta = (key: Bytes, nodeId: string, keyVersion: number, meta: NodeMeta): B64 =>
  toBase64Url(sealJson(key, TAG.nodeMeta, meta, nodeAd(nodeId, keyVersion)));

export const decryptNodeMeta = (key: Bytes, nodeId: string, keyVersion: number, meta: B64): NodeMeta =>
  openJson<NodeMeta>(key, TAG.nodeMeta, fromBase64Url(meta), nodeAd(nodeId, keyVersion));

export type ChildLink = {
  childId: string;
  childVersion: number;
  parentId: string;
  parentVersion: number;
  wrapped: B64;
};

const linkAd = (l: Omit<ChildLink, "wrapped">) =>
  utf8(`${l.childId}:${l.childVersion}<${l.parentId}:${l.parentVersion}`);

export function wrapChildKey(parentKey: Bytes, l: Omit<ChildLink, "wrapped">, childKey: Bytes): ChildLink {
  return { ...l, wrapped: toBase64Url(seal(parentKey, TAG.childKey, childKey, linkAd(l))) };
}

export const unwrapChildKey = (parentKey: Bytes, l: ChildLink): Bytes =>
  open(parentKey, TAG.childKey, fromBase64Url(l.wrapped), linkAd(l));
