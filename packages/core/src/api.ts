// Request/response shapes shared by apps/api and packages/api-client.
// The client is hand-written against these so the open-source packages never import the server.
import type { Grant } from "./grants.ts";
import type { ChildLink } from "./nodes.ts";
import type { TreeNode } from "./resolver.ts";
import type { GroupGrant, GroupVersion, InviteAcceptance, InviteStatement, MemberProof, TeamKeyLink } from "./teams.ts";
import type { AccountBundle, B64, PublicIdentity, Role } from "./wire.ts";

export type ApiErrorBody = { error: string; message: string };

export type RegisterStartReq = { handle: string; registrationRequest: string };
export type RegisterStartRes = { registrationResponse: string };
export type RegisterFinishReq = {
  userId: string;
  handle: string;
  registrationRecord: string;
  bundle: AccountBundle;
  passwordWrap: B64;
  recoveryWrap: B64;
  recoveryAuthHash: B64;
  workspace: { id: string; rootNodeId: string; rootMeta: B64; rootGrant: Grant };
  /** The paid checkout session that pays for the account; required when the server has billing on. */
  checkout?: string;
};
export type SessionRes = { token: string; userId: string };

export type LoginStartReq = { handle: string; startLoginRequest: string };
export type LoginStartRes = { loginId: string; loginResponse: string };
export type LoginFinishReq = { loginId: string; finishLoginRequest: string };
export type MeRes = {
  userId: string;
  handle: string;
  bundle: AccountBundle;
  passwordWrap: B64;
  /** Revision of `bundle.privateData`; the next write must carry this + 1. */
  privateDataRevision: number;
};
export type LoginFinishRes = SessionRes & MeRes;

export type RecoverReq = { handle: string; recoveryAuth: B64 };
export type RecoverRes = {
  recoveryToken: string;
  userId: string;
  recoveryWrap: B64;
  bundle: AccountBundle;
  privateDataRevision: number;
};
export type PasswordStartReq = { registrationRequest: string };
export type PasswordFinishReq = {
  registrationRecord: string;
  passwordWrap: B64;
  recovery?: { recoveryWrap: B64; recoveryAuthHash: B64 };
};

export type SessionInfo = {
  id: string;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
};
/**
 * Whether the account may be deleted (`GET /account/deletion`), or what stops it: owning a team, being managed by
 * one (with its admins' handles), or a hold. Team names are encrypted: the client names the team by its id.
 */
export type AccountDeletionStatus =
  | { ok: true }
  | {
      ok: false;
      code: "team_owner" | "managed" | "account_on_hold";
      team?: { id: string };
      admins?: string[];
    };
export type DeleteAccountReq = { handle: string };
/** Cents refunded for the unused part of a plan (0 when there was nothing to refund). */
export type DeleteAccountRes = { refunded: number };
export type PrivateDataReq = { privateData: B64; revision: number };
export type HandleAvailableRes = { available: boolean; reason?: "format" | "reserved" | "taken" };

export type WorkspaceInfo = {
  id: string;
  kind: "personal" | "team";
  rootNodeId: string;
  role: Role;
  /** Team workspaces: the team they belong to. */
  teamId?: string;
  /** Tasks' system folder at the root, once Tasks was first opened (apps hide it outside Tasks). */
  tasksFolderId: string | null;
  /** The Inbox project in the Tasks folder (personal workspaces, once set up). */
  tasksInboxId: string | null;
  /** Contacts' system folder at the root, once Contacts was first opened (apps hide it outside Contacts). */
  contactsFolderId: string | null;
  /** My contacts, the address book in the Contacts folder (personal workspaces, once set up). */
  contactsBookId: string | null;
  /** Jelly Video's Meetings system folder at the root, once set up (apps hide it outside Video). */
  meetingsFolderId: string | null;
  /** Jelly Reader's system folder at the root, once set up (apps hide it outside Reader). */
  readerFolderId: string | null;
  /** Saved, the collection in the Reader folder (personal workspaces, once set up). */
  readerSavedId: string | null;
};
export type TreeRes = {
  rootId: string;
  nodes: TreeNode[];
  links: ChildLink[];
  grants: Grant[];
  identities: PublicIdentity[];
  /** Absent from older servers: treat as []. */
  groupGrants: GroupGrant[];
  /** Shared-with-me only: the owner of each listed node from a personal workspace. Absent from older servers. */
  owners?: Array<{ nodeId: string; userId: string }>;
};

export type CreateNodeReq = { id: string; parentId: string; kind: string; meta: B64; link: ChildLink };
export type UpdateNodeReq = { keyVersion: number; meta: B64 };
export type MoveNodeReq = { parentId: string; link: ChildLink };

export type GrantEntry = { grant: Grant; identity: PublicIdentity };
export type GroupGrantEntry = { grant: GroupGrant; group: GroupVersion };
/** Shares on a node and its visible ancestors; `chain` is the node then its ancestors, nearest first. */
export type MembersRes = {
  chain: string[];
  entries: GrantEntry[];
  /** Group grants on the same chain, each with its group's current version. Absent from older servers. */
  groupEntries: GroupGrantEntry[];
};
export type RotateReq = {
  keyVersion: number;
  meta: B64;
  childLinks: ChildLink[];
  grants: Grant[];
  parentLink?: ChildLink;
  links?: Array<{ id: string; wrappedNodeKey: B64; wrappedSecret: B64 }>;
  /** Active links of the node nobody on it vouches for (or this account turned off): the server turns them off. */
  droppedLinks?: string[];
  /** Required when the node has content: snapshots re-encrypted under the new key. */
  content?: { snapshots: Array<{ uptoSeq: number; envelope: B64 }> };
};

export type CreateLinkReq = {
  id: string;
  role: "viewer" | "editor";
  authHash: B64;
  keyVersion: number;
  wrappedNodeKey: B64;
  wrappedSecret: B64;
  /** The creator's `signLink` over id, node, role and auth hash. */
  signature: B64;
  /** ISO time, at most a year ahead. Omitted or null: never expires. */
  expiresAt?: string | null;
};
export type LinkStatus = "live" | "paused" | "blocked" | "expired";
export type LinkInfo = {
  id: string;
  role: "viewer" | "editor";
  keyVersion: number;
  wrappedSecret: B64;
  createdBy: string;
  /** The creator's `signLink`; null on links made before links were signed. */
  signature: B64 | null;
  createdAt: string;
  /** Null: never expires. */
  expiresAt: string | null;
  status: LinkStatus;
  /** Why it's paused or blocked, as the owner should read it. */
  statusReason?: string;
};
export type AbuseReason = "csam" | "terrorism" | "illegal" | "copyright" | "malware" | "harassment" | "other";
/** A reviewer's public key; reports are sealed to each so the server can't read them. */
export type ReviewerKey = { userId: string; encPub: B64 };
export type ReportReq = {
  linkId: string;
  reason: AbuseReason;
  /** Optional, so we can tell the reporter what we did. */
  contact?: string;
  sealed: { userId: string; box: B64 }[];
};
export type OpenLinkReq = { auth: B64 };
export type OpenLinkRes = {
  token: string;
  nodeId: string;
  role: "viewer" | "editor";
  keyVersion: number;
  wrappedNodeKey: B64;
};

// ---- Teams ----

/** A built-in group as created with its team: version 1, the creator's key seal and proof, and its root grant. */
export type CreateTeamGroup = {
  groupId: string;
  version: GroupVersion;
  seal: B64;
  proof: MemberProof;
  rootGrant: GroupGrant;
};
export type CreateTeamReq = {
  teamId: string;
  workspace: { id: string; rootNodeId: string; rootMeta: B64 };
  teamKey: TeamKeyLink;
  /** The team signer, sealed to the creator. */
  teamKeySeal: B64;
  everyone: CreateTeamGroup;
  admins: CreateTeamGroup;
  /** TeamMeta under teamMetaKey(everyone). */
  meta: B64;
};
export type TeamRole = "owner" | "admin" | "member";
export type TeamStatus = "invited" | "active" | "suspended" | "removed";
export type TeamGroupInfo = {
  id: string;
  builtin: "everyone" | "admins" | null;
  version: number;
  meta: B64 | null;
  metaVersion: number | null;
  needsRotation: boolean;
  versions: GroupVersion[];
  memberIds: string[];
  /** Each member's stored proof, for clients to verify against the team key before sealing to them. */
  proofs: Array<{ userId: string; proof: MemberProof }>;
};
export type TeamInfo = {
  id: string;
  workspaceId: string;
  rootNodeId: string;
  /** Chat's system folder in the team root, once Chat was first opened (apps hide it outside Chat). */
  channelsFolderId: string | null;
  /** Tasks' system folder in the team root, once Tasks was first opened (apps hide it outside Tasks). */
  tasksFolderId: string | null;
  /** Always null: a team workspace has no Inbox (kept to match WorkspaceInfo). */
  tasksInboxId: string | null;
  /** Contacts' system folder in the team root, once Contacts was first opened (apps hide it outside Contacts). */
  contactsFolderId: string | null;
  /** Always null: a team workspace has no My contacts (kept to match WorkspaceInfo). */
  contactsBookId: string | null;
  /** Jelly Video's Meetings system folder in the team root, once set up (apps hide it outside Video). */
  meetingsFolderId: string | null;
  /** Jelly Reader's system folder in the team root, once set up (apps hide it outside Reader). */
  readerFolderId: string | null;
  /** Always null: a team workspace has no Saved (kept to match WorkspaceInfo). */
  readerSavedId: string | null;
  plan: string;
  role: TeamRole;
  status: TeamStatus;
  managed: boolean;
  meta: B64;
  metaVersion: number;
  teamKeys: TeamKeyLink[];
  /** An admin left: the next admin client online rotates the team key (POST /teams/:id/keys/rotate). */
  needsKeyRotation: boolean;
  /** Empty unless the caller is an active member. */
  groups: TeamGroupInfo[];
  /**
   * People who left or were removed, with their last `everyone` proof (empty unless the caller is an active
   * member). Clients trust grants they made only on items flagged for a new key, to read and re-key those.
   */
  formerMembers: FormerMemberInfo[];
  /** The caller's pending joined invite, while their status is `invited` (to accept or decline). */
  inviteId?: string;
  /** The handle of the admin who made that invite. */
  invitedBy?: string;
};
export type FormerMemberInfo = { userId: string; signPub: B64; proof: MemberProof };
export type TeamMetaReq = { meta: B64; metaVersion: number };
export type TransferTeamReq = { userId: string };
/**
 * A new team signing key: sealed to every active owner and admin, with everything bound to the team key
 * version re-signed under it (every group's current version, every member's proof, every pending invite).
 */
export type RotateTeamKeyReq = {
  link: TeamKeyLink;
  seals: Array<{ userId: string; sealed: B64 }>;
  groupVersions: GroupVersion[];
  proofs: Array<{ groupId: string; userId: string; proof: MemberProof }>;
  invites: Array<{ inviteId: string; statement: InviteStatement }>;
};
export type MyGroupKeysRes = {
  seals: Array<{ groupId: string; version: number; sealed: B64 }>;
  teamSeals: Array<{ teamId: string; version: number; sealed: B64 }>;
};

// ---- Members ----

/** A team member as other members see them (removed ones only for admins asking with `?all=1`). */
export type TeamMemberInfo = {
  userId: string;
  handle: string;
  role: TeamRole;
  status: TeamStatus;
  managed: boolean;
  /** The account was deleted (a tombstone: "Former member"); only removed members can be. */
  deleted: boolean;
  identity: PublicIdentity;
};
/**
 * A removed member as non-admins see them with `?all=1`: enough to name an author who left ("(left)" or, once
 * the account is deleted, "Former member"), nothing more.
 */
export type RemovedMemberInfo = { userId: string; handle: string; status: "removed"; deleted: boolean };
/**
 * Promotion: the new admin added to `admins` (a proof at its current version and its key sealed to them) and the
 * current team signer sealed to them. Demotion: `admins` moves to its next version without them, then the team
 * key rotates (built against the state after that `next`: admins at its new version, their proofs included).
 */
export type ChangeRoleReq =
  | { role: "admin"; admins: { proof: MemberProof; seal: B64 }; teamKeySeal: B64 }
  | { role: "member"; admins: { next: GroupNext }; teamKey: RotateTeamKeyReq };
/**
 * Removing (or deleting) a member: a `next` for every group they are in (`everyone` with the team and group
 * names re-encrypted, `admins` if they are one), and for an admin a team key rotation built against the state
 * after those `next`s.
 */
export type RemoveMemberReq = {
  groups: Array<{ groupId: string; next: GroupNext }>;
  teamKey?: RotateTeamKeyReq;
};

// ---- Groups ----

/** A member as an admin adds them: a proof at the group's current version and team key, and the key sealed to them. */
export type GroupMemberEntry = { userId: string; proof: MemberProof; seal: B64 };
/** A named group: version 1 signed by the current team key, its name under the team meta key, and its first members. */
export type CreateGroupReq = {
  groupId: string;
  version: GroupVersion;
  /** GroupMeta under the team meta key for everyone@metaVersion. */
  meta: B64;
  metaVersion: number;
  members: GroupMemberEntry[];
};
export type GroupMetaReq = { meta: B64; metaVersion: number };
export type AddGroupMemberReq = GroupMemberEntry;
/**
 * A group's next version, made by an admin's client on removal or rotation: the new key signed by the current
 * team key, sealed to exactly the remaining members (with fresh statements at the new version) and to every
 * pending invite naming the group (re-signed for the new version). For `everyone`, the team name and every
 * named group's name re-encrypted under the new meta key.
 */
export type GroupNext = {
  version: GroupVersion;
  seals: Array<{ userId: string; sealed: B64 }>;
  proofs: Array<{ userId: string; proof: MemberProof }>;
  inviteSeals: Array<{ inviteId: string; sealed: B64 }>;
  invites: Array<{ inviteId: string; statement: InviteStatement }>;
  meta?: { team?: B64; groups?: Array<{ groupId: string; meta: B64 }> };
};
export type GroupNextReq = { next: GroupNext };

// ---- Invites ----

export type GroupKeySealWire = { groupId: string; version: number; sealed: B64 };
/**
 * An admin's invite, signed by the current team key. `statement.groupVersions` names `everyone` and any named
 * groups at their current versions; `seals` cover exactly those. Managed: `authHash` = base64url(sha256(inviteAuth)),
 * seals go to `invitePub`, the handle is `local@<verified team domain>`. Joined: the handle is an existing user's,
 * seals go to their key, and `proofs` hold a team statement per group.
 */
export type CreateInviteReq = {
  statement: InviteStatement;
  authHash?: B64;
  seals: GroupKeySealWire[];
  proofs?: Array<{ groupId: string; proof: MemberProof }>;
};
export type CreateInviteRes = { inviteId: string; expiresAt: string };
/** A pending invite as admins see it (expired ones too, until revoked). */
export type TeamInviteInfo = {
  id: string;
  kind: "managed" | "joined";
  handle: string;
  userId: string | null;
  statement: InviteStatement;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
};
export type OpenInviteReq = { inviteId: string; auth: B64 };
/** What the invite link opens: the team's key chain and name, and the group keys sealed to the invite key. */
export type OpenInviteRes = {
  invite: InviteStatement;
  teamKeys: TeamKeyLink[];
  teamMeta: B64;
  metaVersion: number;
  seals: GroupKeySealWire[];
  groupVersions: GroupVersion[];
  /** A 30-minute invite session for register/start and activate. */
  token: string;
};
/** Sign-up with the invite's handle, the acceptance signed with the invite key, and the group keys re-sealed to the new account. */
export type ActivateReq = RegisterFinishReq & { acceptance: InviteAcceptance; seals: GroupKeySealWire[] };

// ---- Chat ----

/** A node created restricted at key version 1: no parent link, its key reachable only through these shares. */
export type RestrictedCreateReq = {
  id: string;
  parentId: string;
  kind: string;
  meta: B64;
  grants: Grant[];
  groupGrants: GroupGrant[];
};
/** The Channels system folder (under the team root) and #general (under the folder), both linked. */
export type ChatSetupReq = { folder: CreateNodeReq; general: CreateNodeReq };
export type ChatSetupRes = { channelsFolderId: string; generalId: string };
export type CreateChannelReq =
  | { teamId: string; visibility: "public"; node: CreateNodeReq; ownerGrant: Grant }
  | { teamId: string; visibility: "private"; node: RestrictedCreateReq };
/** Participants are 2–8 active team members including the caller; each gets a direct share (the caller: owner). */
export type CreateDmReq = { teamId: string; participants: string[]; node: RestrictedCreateReq };
/** `created` is false when an existing DM between exactly these people was returned. */
export type CreateChannelRes = { id: string; created: boolean };
export type ChatNotify = "all" | "mentions" | "none";
export type ChatSettings = { muted: boolean; notify: ChatNotify };
export type ChatSettingsReq = { muted?: boolean; notify?: ChatNotify };
export type ChatChannelInfo = {
  node: TreeNode;
  visibility: "public" | "private" | "dm";
  /** Public channels: has joined. Private channels and DMs: always (access is membership). */
  joined: boolean;
  /** Top-level messages by others after `lastReadSeq` that aren't deleted. */
  unread: number;
  lastReadSeq: number;
  settings: ChatSettings;
  /** DMs: the people holding a direct share on it (who's really in it), sorted. */
  participants?: string[];
  /** DMs: some group holds a share on it (a DM never should: its people are fixed). */
  hasGroupGrants?: boolean;
};
export type ChatChannelsRes = {
  channelsFolderId: string | null;
  generalId: string | null;
  channels: ChatChannelInfo[];
  dms: ChatChannelInfo[];
};

/** Edits update a message in place, so there is no "edit" kind. */
export type ChatEntryKind = "message" | "reaction" | "pin" | "unpin" | "system";
/** A chat entry as the server stores it: kind, thread root and target in the clear, the rest sealed and signed. */
export type ChatEntryWire = {
  id: string;
  channelId: string;
  seq: number | null;
  kind: ChatEntryKind;
  threadRoot: string | null;
  target: string | null;
  /**
   * A thread reply its author also sent to the channel (unsigned: the server could hide one; clients show it in
   * the channel only if the signed content says so too).
   */
  inChannel?: boolean;
  /**
   * The server took this entry as the record of how a huddle went: under the id kept for it, from someone who
   * was in that call, the first posted. The server's word (it knows who was in a call; the clients of people
   * who weren't don't): without it no entry counts as such a record.
   */
  callEnd?: boolean;
  keyVersion: number;
  /** Null once deleted. */
  envelope: B64 | null;
  signature: B64 | null;
  authorId: string;
  createdAt: string;
  editedAt: string | null;
  deletedAt: string | null;
};
/**
 * One entry, author = the caller, under the channel's current key version. `threadRoot` (messages only) is a
 * top-level message of the channel; `target` (reactions, pins, unpins) a message of the channel.
 */
export type PostChatEntryReq = {
  id: string;
  kind: ChatEntryKind;
  threadRoot?: string | null;
  target?: string | null;
  /** Thread replies only: also shown in the channel's pages. */
  inChannel?: boolean;
  keyVersion: number;
  envelope: B64;
  signature: B64;
};
export type PostChatEntryRes = { entry: ChatEntryWire };
/** An edit replaces the message's envelope and signature, under the current key version. */
export type EditChatEntryReq = { keyVersion: number; envelope: B64; signature: B64 };
export type ChatThreadStats = {
  rootId: string;
  replies: number;
  lastReplyAt: string;
  /** User ids of up to three distinct reply authors, most recent first. */
  authors: string[];
};
/**
 * A page of top-level messages and system entries (and thread replies also sent to the channel), newest first. With `before` (and no `after`): the newest
 * `limit` entries before it. With `after`: the oldest `limit` entries after it (catching up). `hasMore`: there
 * are more beyond the page in that direction. `related`: the reactions, pins and unpins targeting the page's
 * entries. `threads`: reply counts, last reply time and recent reply authors for the page's entries that have replies.
 */
export type ChatEntriesRes = {
  entries: ChatEntryWire[];
  related: ChatEntryWire[];
  threads: ChatThreadStats[];
  hasMore: boolean;
};
/** A thread's root and replies (oldest first) plus the reactions, pins and unpins targeting any of them. */
export type ChatThreadRes = { root: ChatEntryWire; replies: ChatEntryWire[]; related: ChatEntryWire[] };
export type ChatEntryRes = { entry: ChatEntryWire };
/** Moves the caller's read pointer forward (never back), up to the channel's newest entry. */
export type ChatReadReq = { seq: number };
export type ChatReadRes = { lastReadSeq: number };
/** `envelope` wraps version `keyVersion - 1`'s key under version `keyVersion`'s. */
export type ChatKeyHistoryRes = { history: Array<{ keyVersion: number; envelope: B64 }> };

// ---- Tasks ----

/**
 * The workspace's Tasks system folder (linked at the workspace root) and, in a personal workspace only, the
 * Inbox project (kind `task-project`, linked in the folder).
 */
export type TasksSetupReq = { folder: CreateNodeReq; inbox?: CreateNodeReq };
/** `inboxId` is null in a team workspace (no Inbox there). */
export type TasksSetupRes = { tasksFolderId: string; inboxId: string | null };

// ---- Reader ----

/**
 * Sets up the workspace's Reader folder (at the root) and, in a personal workspace, Saved (kind `reader-collection`,
 * linked in the folder).
 */
export type ReaderSetupReq = { folder: CreateNodeReq; saved?: CreateNodeReq };
/** `savedId` is null in a team workspace (no Saved there). */
export type ReaderSetupRes = { readerFolderId: string; savedId: string | null };
/**
 * One of a person's items as the item store returns it; `envelope` is sealed (base64url). Which feed it's from is
 * only inside the envelope.
 */
export type ReaderItemWire = {
  id: string;
  seq: number;
  unread: boolean;
  starred: boolean;
  envelope: string;
  createdAt: string;
};
export type ReaderItemsRes = { items: ReaderItemWire[]; next: number | null };
export type ReaderPutReq = { items: Array<{ id: string; envelope: string }> };
export type ReaderPutRes = { seq: number };
/** Exactly one selector: `ids` (at most 500) or `createdUpTo` (ISO, compared with the items' creation time). */
export type ReaderPatchReq = {
  ids?: string[];
  createdUpTo?: string;
  unread?: boolean;
  starred?: boolean;
};
/** Rows whose flags changed. */
export type ReaderPatchRes = { updated: number };
export type ReaderDeleteRes = { deleted: number };
/** Exactly one selector: `ids` (at most 500) or `unstarredBefore` (ISO, by creation time). */
export type ReaderDeleteReq = { ids?: string[]; unstarredBefore?: string };

// ---- Contacts ----

/**
 * The workspace's Contacts system folder (linked at the workspace root) and, in a personal workspace only, the
 * My contacts address book (kind `contact-book`, linked in the folder).
 */
export type ContactsSetupReq = { folder: CreateNodeReq; book?: CreateNodeReq };
/** `contactsBookId` is null in a team workspace (no My contacts there). */
export type ContactsSetupRes = { contactsFolderId: string; contactsBookId: string | null };

// ---- Jelly Video ----

/** The workspace's Meetings system folder (linked at the workspace root); meeting rooms (kind `meeting`) go in it. */
export type MeetingsSetupReq = { folder: CreateNodeReq };
export type MeetingsSetupRes = { meetingsFolderId: string };

/** A call's media key for one epoch, sealed under the space's node key at `keyVersion` (`jelly/call-key@1`). */
export type CallEpoch = { epoch: number; keyVersion: number; envelope: B64 };
/** `deviceId`: 1–64 of A–Z a–z 0–9 _ -, the device's half of the media server identity `userId:deviceId`. */
export type CallJoinReq = { deviceId: string };
export type CallJoinRes = {
  callId: string;
  /** Where the media server is (ws/wss). */
  livekitUrl: string;
  /**
   * The media server token for `userId:deviceId` in this call's room; good for 6 hours. Connect with it
   * within 2 minutes of the join: a device let in that hasn't connected by then is forgotten and dropped.
   */
  token: string;
  epochs: CallEpoch[];
  /** Whether the caller may mute and remove others, lock and end the call (editor on the space). */
  host: boolean;
  locked: boolean;
  /** Someone was removed or the space was re-keyed: the call is owed a new epoch. */
  needsEpoch: boolean;
  /** As `CallKeysRes.removed`. */
  removed?: string[];
  startedAt: string;
  /** The server's clock at the join (ISO): epochs are timed by it, so a client far off it should say so. */
  now: string;
};
export type CallKeyReq = CallEpoch;
export type CallKeysRes = {
  epochs: CallEpoch[];
  needsEpoch: boolean;
  locked: boolean;
  /**
   * The people (user ids) a host removed from this call. Clients stop taking them as hosts at once: their
   * requests to mute or lower a hand count for nothing, before any new epoch shuts them out. The server's word,
   * which here only ever takes something away.
   */
  removed?: string[];
};
export type CallLeaveReq = { deviceId: string };
/** `identity`: `userId:deviceId`. `track`: the media server's track id (a LiveKit track SID). */
export type CallMuteReq = { identity: string; track: string };
export type CallRemoveReq = { identity: string };
export type CallLockReq = { locked: boolean };
/** A live call with someone in it, on a space the caller can open. */
export type ActiveCall = { nodeId: string; callId: string; startedAt: string; userIds: string[]; locked: boolean };
/**
 * What the relay tells sockets subscribed to a call space: `started` (a new call), `changed` (people or the
 * lock), `epoch` (a new epoch is owed or was posted: fetch the keys), `ended`.
 */
export type CallState = "started" | "changed" | "epoch" | "ended";

// ---- Billing ----
export type BillingPlan = "basic" | "plus";
/** `private` prices include VAT; `business` prices exclude it (VAT is added at checkout). */
export type BillingBuyer = "private" | "business";
export type BillingInterval = "monthly" | "yearly";
/** `accountId`: a lapsed billing account of the caller's to revive with this checkout. */
export type CheckoutReq = {
  plan: BillingPlan;
  interval: BillingInterval;
  buyer: BillingBuyer;
  seats?: number;
  accountId?: string;
};
export type CheckoutRes = { sessionId: string; url: string };
export type ClaimRes = {
  paid: boolean;
  /** Checkout is finished but the payment hasn't settled yet (a bank debit takes days): not paid, nothing to redo. */
  pending: boolean;
  claimed: boolean;
  plan: BillingPlan;
  buyer: BillingBuyer;
};
export type BillingAccountInfo = {
  id: string;
  plan: BillingPlan | "comp";
  /** Null for comp. */
  buyer: BillingBuyer | null;
  interval: BillingInterval | null;
  seats: number;
  status: string;
  /** ISO dates. */
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  lockedAt: string | null;
  deleteAfter: string | null;
  teamId: string | null;
  /** The caller owns it or is an owner or admin of its team. */
  canManage: boolean;
  /** Has a Stripe customer, so the portal can open. */
  portal: boolean;
};
export type BillingRes = { entitled: boolean; accounts: BillingAccountInfo[] };
export type PortalReq = { accountId: string };
export type PortalRes = { url: string };

// Push: server-sent reminders (docs/superpowers/specs/2026-10-21-push-design.md §4).

export type PushEnvironment = "production" | "sandbox";
/** `GET /push/config`: whether this server sends pushes (APNs configured). */
export type PushConfigRes = { enabled: boolean };
/** One of the account's push devices (`GET /push/devices`); tokens are never returned. `mail`: new mail is pushed. */
export type PushDeviceWire = { id: string; publicKey: string; mail: boolean; createdAt: string };
/**
 * `POST /push/devices`: the APNs device token (hex), and the install's X25519 push public key (base64url). `mail`
 * also pushes new mail to it (off when left out).
 */
export type AddPushDeviceReq = { token: string; environment: PushEnvironment; publicKey: string; mail?: boolean };
/** `PATCH /push/devices/:id`: switches new-mail pushes. */
export type PatchPushDeviceReq = { mail: boolean };
export type AddPushDeviceRes = { id: string };
/** A reminder at `at` (ISO): `sealed` maps a push device id to the text sealed to it (base64url). */
export type PushReminderWire = { key: string; at: string; sealed: Record<string, string> };
/**
 * `PUT /push/reminders/:sourceId`: replaces all of the caller's reminders for the source. `version` is an event's
 * `updatedAt` as received, or a task project's highest applied update seq (a decimal string).
 */
export type PutPushRemindersReq = { version: string; reminders: PushReminderWire[] };

/** A disposable receiving address (<label>.<random>@<mail domain>) delivering into the owner's mailbox. */
export type MailAliasWire = {
  id: string;
  address: string;
  state: "enabled" | "disabled";
  newsletter: boolean;
  createdAt: string;
};
/** The address a label would get, with a short-lived token to create exactly that alias. */
export type AliasPreviewRes = { address: string; token: string };

/** Jelly Reader: a batch of blinded anonymous tokens (base64url, at most 100) for the current epoch. */
export type ReaderTokensReq = { epoch: number; blinded: string[] };
/** The evaluated batch with its proof, and how many tokens today's allowance still covers. */
export type ReaderTokensRes = { epoch: number; evaluated: string[]; proof: string; remaining: number };
export type ReaderAllowanceRes = { remaining: number; epoch: number };
