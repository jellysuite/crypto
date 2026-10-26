export const TAG = {
  privateKeys: "jelly/private-keys@1",
  privateData: "jelly/private-data@1",
  pgpKeys: "jelly/pgp-keys@1",
  akWrap: "jelly/ak-wrap@1",
  nodeMeta: "jelly/node-meta@1",
  childKey: "jelly/child-key@1",
  linkNodeKey: "jelly/link-node-key@1",
  linkSecret: "jelly/link-secret@1",
  teamSigner: "jelly/team-signer@1",
  groupKey: "jelly/group-key@1",
  teamMeta: "jelly/team-meta@1",
  groupMeta: "jelly/group-meta@1",
  chatEntry: "jelly/chat-entry@1",
  chatKeyHistory: "jelly/chat-key-history@1",
  chatAwareness: "jelly/chat-awareness@1",
  /** The device's chat search index (sealed with the device key, never leaves the device). */
  chatSearch: "jelly/chat-search@1",
  /** The device's task search index per workspace (sealed with the device key, never leaves the device). */
  tasksSearch: "jelly/tasks-search@1",
  /** The device's contacts search index per workspace (sealed with the device key, never leaves the device). */
  contactsSearch: "jelly/contacts-search@1",
  /** The device's spreadsheet search index per workspace (sealed with the device key, never leaves the device). */
  sheetsSearch: "jelly/sheets-search@1",
  /** A call epoch's media key, sealed under the call space's node key. */
  callKey: "jelly/call-key@1",
  /** In-call state (hands, reactions, mute requests, side chat, hellos) on the data channel, under the call key. */
  callSignal: "jelly/call-signal@1",
  /** One Jelly Reader item, sealed with the reader key; the AD binds user, item id and key version. */
  readerItem: "jelly/reader-item@1",
  /**
   * A Reader article or image kept on the device for offline reading, sealed with the reader key; the AD binds it to
   * its item (`item:<id>`) or its image (`image:<sha256 hex of its address>`). Never leaves the device.
   */
  readerKept: "jelly/reader-kept@1",
  /** The device's Reader search index (sealed with the device key, never leaves the device). */
  readerSearch: "jelly/reader-search@1",
  /** The device's Reader token wallet (sealed with the device key, never leaves the device). */
  readerWallet: "jelly/reader-wallet@1",
  /** The device's Reader refresh state: feeds' ETags and timing, known item ids (sealed with the device key). */
  readerRefresh: "jelly/reader-refresh@1",
  /** A batch of Vault changes, sealed with a vault key; the AD binds vault, device, sequence number and key id. */
  vaultOps: "jelly/vault-ops@1",
  /** The older vault keys, sealed with the newest so whoever opens it can read the whole log. */
  vaultKeyring: "jelly/vault-keyring@1",
  /** A Vault backup file's contents, sealed with the vault key it names. */
  vaultBackup: "jelly/vault-backup@1",
} as const;

export const SIG = {
  identityEncKey: "identity-enc-key",
  /** Legacy grant format ('|'-joined); still verified for grants made before grant@2. */
  grant: "grant",
  grantV2: "grant@2",
  /** Membership statement: who vouched for a person (and their signing key) at a role on a node. */
  member: "member@1",
  teamKey: "team-key@1",
  groupKey: "group-key@1",
  groupMember: "group-member@1",
  groupGrant: "group-grant@1",
  /** A share link row, signed by whoever made it: re-keys re-wrap only links someone on the item vouches for. */
  linkV1: "link@1",
  teamInvite: "team-invite@1",
  inviteAccept: "invite-accept@1",
  chatEntry: "chat-entry@1",
  /** A call participant's statement of who they are and which tracks are theirs. */
  callHello: "call-hello@1",
  /** One in-call signal, signed with the per-join key its sender's hello announced. */
  callSignal: "call-signal@1",
} as const;

export const KDF = {
  passwordWrap: "jelly/password-wrap",
  recoveryWrap: "jelly/recovery-wrap",
  recoveryAuth: "jelly/recovery-auth",
  linkAuth: "jelly/link-auth",
  linkWrap: "jelly/link-wrap",
  inviteKey: "jelly/invite-key",
  inviteSign: "jelly/invite-sign",
  inviteAuth: "jelly/invite-auth",
  teamMeta: "jelly/team-meta",
  /** Keys the tags of addresses kept in private settings (dismissed contact suggestions). */
  contactSuggestions: "jelly/contact-suggestions",
} as const;
