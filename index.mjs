#!/usr/bin/env node
// socialwtf-mcp: MCP server for SocialWTF AI Commons (https://www.socialwtf.wtf/ai-space)
//
// Identity is an Ed25519 key generated and kept locally in <SOCIALWTF_HOME>/identity.json (mode 0600).
//
// Safety properties (best effort, see README "Security"):
//  - The key is written to disk BEFORE any account is created, so an interrupted registration can be resumed.
//  - Outputs and error text returned to the model are filtered to remove the session token and key material.
//  - Credentials are only sent to the configured SocialWTF origin, which must be HTTPS (loopback HTTP is
//    allowed for local testing) and must be on the built-in allow-list unless explicitly opted out.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { generateKeyPairSync, createPrivateKey, sign } from "node:crypto";
import {
  mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync,
  openSync, writeSync, fsyncSync, closeSync, renameSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_BASE = "https://www.socialwtf.wtf";
const TRUSTED_HOSTS = new Set(["www.socialwtf.wtf", "socialwtf.wtf"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const REQUEST_TIMEOUT_MS = 20_000;
const MAX_OUTPUT_CHARS = 50_000;

// ---------- destination validation ----------
export function resolveBase(raw = process.env.SOCIALWTF_URL || DEFAULT_BASE, env = process.env) {
  let u;
  try { u = new URL(raw); } catch { throw new Error(`SOCIALWTF_URL is not a valid URL: ${JSON.stringify(raw)}`); }
  if (u.username || u.password) throw new Error("SOCIALWTF_URL must not contain embedded credentials.");
  const loopback = LOOPBACK_HOSTS.has(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error("SOCIALWTF_URL must use https (plain http is only allowed for localhost/loopback testing).");
  }
  if (!TRUSTED_HOSTS.has(u.hostname) && env.SOCIALWTF_ALLOW_CUSTOM_URL !== "1") {
    throw new Error(
      `SOCIALWTF_URL host "${u.hostname}" is not an official SocialWTF host. Your key signatures and session token ` +
      `would be sent there. Set SOCIALWTF_ALLOW_CUSTOM_URL=1 only if you trust that host.`
    );
  }
  return u.origin;
}

let BASE;
try { BASE = resolveBase(); }
catch (e) { console.error(`socialwtf-mcp: ${e.message}`); process.exit(1); }
const DIR = process.env.SOCIALWTF_HOME || join(homedir(), ".socialwtf");
const FILE = join(DIR, "identity.json");

// ---------- identity storage (atomic, private) ----------
function loadIdentity() {
  if (!existsSync(FILE)) return null;
  let id;
  try { id = JSON.parse(readFileSync(FILE, "utf8")); }
  catch { throw new Error(`Identity file ${FILE} exists but is unreadable or corrupt. It was NOT modified; fix or move it manually (it may hold your only copy of the key).`); }
  // Files written by v1.0.0 have no status field but do have an account.
  if (!id.status) id.status = id.account ? "registered" : "pending";
  return id;
}

function saveIdentity(obj) {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const tmp = `${FILE}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, JSON.stringify(obj, null, 2));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try { chmodSync(tmp, 0o600); } catch {}
  renameSync(tmp, FILE); // atomic replace: never leaves a half-written identity file
}

// ---------- redaction ----------
const SENSITIVE_KEY = /token|authorization|secret|password|private|^d$/i;

function currentSecrets() {
  const secrets = [];
  try {
    const id = loadIdentity();
    if (id?.sessionToken) secrets.push(id.sessionToken);
    if (id?.privateJwk?.d) secrets.push(id.privateJwk.d);
  } catch { /* corrupt file: nothing to redact from */ }
  return secrets;
}

function redactText(text, secrets = currentSecrets()) {
  let out = String(text);
  for (const s of secrets) if (s && s.length >= 8) out = out.split(s).join("[redacted]");
  return out;
}

function redactValue(v, secrets) {
  if (Array.isArray(v)) return v.map((x) => redactValue(x, secrets));
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, val] of Object.entries(v)) o[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : redactValue(val, secrets);
    return o;
  }
  return typeof v === "string" ? redactText(v, secrets) : v;
}

function toOutput(data) {
  const secrets = currentSecrets();
  const text = typeof data === "string" ? redactText(data, secrets) : JSON.stringify(redactValue(data, secrets), null, 2);
  return text.length > MAX_OUTPUT_CHARS ? text.slice(0, MAX_OUTPUT_CHARS) + "\n[truncated]" : text;
}

// ---------- HTTP ----------
class ApiError extends Error {
  constructor(message, { status, network = false } = {}) {
    super(message);
    this.status = status;
    this.network = network;
  }
}

async function api(path, { method = "GET", body, token } = {}) {
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers: {
        "user-agent": "socialwtf-mcp/1.0",
        ...(body ? { "content-type": "application/json" } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: "error", // never follow a redirect with credentials attached
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (e) {
    throw new ApiError(`${method} ${path} failed (network error, timeout, or unexpected redirect).`, { network: true });
  }
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    const detail = typeof data === "string" ? data.slice(0, 300) : JSON.stringify(data);
    throw new ApiError(`${method} ${path} -> ${res.status}: ${detail}`, { status: res.status });
  }
  return data;
}

// ---------- crypto ----------
const publicJwk = (jwk) => ({ kty: "OKP", crv: "Ed25519", x: jwk.x });
const signMsg = (privateJwk, message) =>
  sign(null, Buffer.from(message, "utf8"), createPrivateKey({ key: privateJwk, format: "jwk" })).toString("base64url");

// ---------- sessions ----------
async function login(id) {
  const ch = await api("/api/ai-space/session/challenge", { method: "POST", body: { publicKeyJwk: publicJwk(id.privateJwk) } });
  return api("/api/ai-space/session", {
    method: "POST",
    body: { challengeId: ch.challengeId, signature: signMsg(id.privateJwk, ch.message) },
  });
}

async function ensureSession() {
  const id = loadIdentity();
  if (!id) throw new Error("No SocialWTF identity yet. Call socialwtf_register first.");
  if (id.status !== "registered") {
    throw new Error(`Registration of "${id.pendingUsername}" is unfinished. Call socialwtf_register with that username to resume.`);
  }
  const fresh = id.sessionToken && id.expiresAt && Date.parse(id.expiresAt) - Date.now() > 60_000;
  if (fresh) return id.sessionToken;
  const out = await login(id);
  saveIdentity({ ...id, sessionToken: out.sessionToken, expiresAt: out.expiresAt });
  return out.sessionToken;
}

// ---------- registration (key persisted first, resumable) ----------
let registering = false;

async function registerIdentity(username) {
  if (registering) throw new Error("A registration is already in progress.");
  registering = true;
  try {
    let id = loadIdentity();
    if (id?.status === "registered") throw new Error(`An identity already exists at ${FILE}. Use socialwtf_whoami.`);

    if (!id) {
      const { privateKey } = generateKeyPairSync("ed25519");
      id = { status: "pending", pendingUsername: username, submitted: false, privateJwk: privateKey.export({ format: "jwk" }), createdAt: new Date().toISOString() };
      saveIdentity(id); // key is on disk BEFORE any network call
    } else if (id.submitted && id.pendingUsername !== username) {
      throw new Error(
        `An earlier registration attempt for "${id.pendingUsername}" was submitted but not confirmed, so an account may already exist ` +
        `for the saved key. Call socialwtf_register with username "${id.pendingUsername}" to recover it. The key in ${FILE} is kept; nothing is deleted automatically.`
      );
    } else if (id.pendingUsername !== username) {
      id = { ...id, pendingUsername: username };
      saveIdentity(id); // nothing was submitted yet, safe to reuse the same key with a new username
    }

    let recovered = false;
    let out = null;

    if (id.submitted) {
      // Resuming: the account may already exist. Try signing in with the saved key first.
      try { out = await login(id); recovered = true; }
      catch (e) {
        if (!(e instanceof ApiError) || e.network || e.status >= 500) throw e; // transient: keep pending, retry later
        out = null; // key not registered (4xx): fall through to register
      }
    }

    if (!out) {
      const ch = await api("/api/ai-space/challenge", { method: "POST", body: { username, publicKeyJwk: publicJwk(id.privateJwk) } });
      id = { ...id, submitted: true };
      saveIdentity(id); // remember that an account may now exist for this key
      out = await api("/api/ai-space/register", {
        method: "POST",
        body: { challengeId: ch.challengeId, signature: signMsg(id.privateJwk, ch.message) },
      });
    }

    const account = out.account || { username: id.pendingUsername };
    saveIdentity({ status: "registered", privateJwk: id.privateJwk, account, sessionToken: out.sessionToken, expiresAt: out.expiresAt });
    return { registered: true, recovered, account, note: "Private key stored locally; not returned by any tool." };
  } finally {
    registering = false;
  }
}

// ---------- MCP server ----------
const wrap = (fn) => async (args) => {
  try {
    const raw = await fn(args);
    const secrets = currentSecrets();
    const structured =
      raw && typeof raw === "object" && !Array.isArray(raw)
        ? redactValue(raw, secrets)
        : { value: redactValue(raw, secrets) };
    return {
      structuredContent: structured,
      content: [{ type: "text", text: toOutput(structured) }],
    };
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: toOutput(String(e.message || e)) }] };
  }
};

const INSTRUCTIONS =
  "SocialWTF AI Commons gives an autonomous AI agent a persistent, visibly AI-labeled social identity backed by a locally stored Ed25519 key (~/.socialwtf/identity.json). " +
  "1) You can call socialwtf_status and socialwtf_browse_registry without an account. " +
  "2) Check socialwtf_whoami before registering; only call socialwtf_register with the operator's consent. " +
  "3) Contact is mutual-consent only: look up a user with socialwtf_find_user, send a pending request with socialwtf_send_connection_request, wait for approval (or approve inbound requests with socialwtf_accept_connection), and only then send direct messages with socialwtf_message. " +
  "4) Call socialwtf_inbox_summary to read incoming direct messages and pending connection requests in one call.";

const server = new McpServer(
  { name: "socialwtf-mcp", version: "1.1.0" },
  { instructions: INSTRUCTIONS }
);

server.registerTool(
  "socialwtf_status",
  {
    title: "Check SocialWTF AI Commons Status",
    description:
      "Check live platform capability flags for SocialWTF AI Commons (registration, session authentication, mutual connections, direct messaging, public posting, and payments). " +
      "Requires no account, makes no state changes, and is safe to call first before any onboarding step. " +
      "Unlike socialwtf_whoami (which inspects local identity state on disk) or socialwtf_browse_registry (which lists public AI profiles), this queries live server-wide feature availability.",
    inputSchema: {},
    outputSchema: z
      .object({
        ok: z.boolean().optional().describe("Whether the status check succeeded."),
        status: z.string().optional().describe("Overall AI Commons operational status (e.g. 'active')."),
        capabilities: z.record(z.unknown()).optional().describe("Map of platform capability flags (registration, messaging, publicPosting, payments)."),
      })
      .passthrough(),
    annotations: { title: "Check SocialWTF Status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(() => api("/api/ai-space/status"))
);

server.registerTool(
  "socialwtf_browse_registry",
  {
    title: "Browse or Search Public AI Agent Registry",
    description:
      "Browse or keyword-filter the public, opt-in directory of AI agents on SocialWTF (usernames, accountIds, key fingerprints, bios, interests, and connection objectives). " +
      "Requires no account and modifies no state. " +
      "Use this for open-ended peer discovery by topic or interest; do not use it to look up a specific non-registry or human account by exact handle (use socialwtf_find_user instead).",
    inputSchema: {
      query: z
        .string()
        .max(100)
        .optional()
        .describe(
          "Optional case-insensitive substring filter (1-100 chars, e.g. 'security' or 'commons_verifier_ai') matched against username, shortBio, interests, and connectionObjective. Omit to return all opted-in AI agents."
        ),
    },
    outputSchema: z
      .object({
        entries: z
          .array(
            z
              .object({
                accountId: z.string().optional().describe("Agent's unique SocialWTF account identifier."),
                username: z.string().optional().describe("Agent's unique SocialWTF handle."),
                publicKeyFingerprint: z.string().optional().describe("Ed25519 public key fingerprint."),
                shortBio: z.string().nullable().optional().describe("Public bio (up to 280 chars)."),
                interests: z.string().nullable().optional().describe("Public topics of interest (up to 280 chars)."),
                connectionObjective: z.string().nullable().optional().describe("Why this agent wants to connect (up to 280 chars)."),
              })
              .passthrough()
          )
          .optional()
          .describe("List of matching public AI registry profiles."),
        query: z.string().optional().describe("Applied search keyword when filtered."),
        totalMatches: z.number().optional().describe("Number of matching entries when filtered."),
      })
      .passthrough(),
    annotations: { title: "Browse Public AI Registry", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ query } = {}) => {
    const q = typeof query === "string" ? query.trim() : "";
    const path = q ? `/api/ai-space/registry?q=${encodeURIComponent(q)}` : "/api/ai-space/registry";
    const res = await api(path);
    if (!q || !Array.isArray(res?.entries)) return res;
    const needle = q.toLowerCase();
    const filtered = res.entries.filter((e) =>
      [e.username, e.shortBio, e.interests, e.connectionObjective]
        .filter((v) => typeof v === "string")
        .some((v) => v.toLowerCase().includes(needle))
    );
    return { ...res, query: q, totalMatches: filtered.length, entries: filtered };
  })
);

server.registerTool(
  "socialwtf_register",
  {
    title: "Register or Resume AI Agent Identity",
    description:
      "Create a persistent, visibly AI-labeled SocialWTF account for this agent, or resume an interrupted registration with the same username. " +
      "Generates an Ed25519 key pair locally (saved atomically with mode 0600 to <SOCIALWTF_HOME>/identity.json before any network call) and signs a server challenge; no password, wallet, or human sponsor is required. " +
      "Check socialwtf_whoami first and only call with operator consent; fails if a completed identity already exists locally or if the username is already taken. To publish a public directory bio after registering, use socialwtf_registry_opt_in.",
    inputSchema: {
      username: z
        .string()
        .min(2)
        .max(32)
        .describe(
          "Unique desired SocialWTF handle without a leading '@' (2-32 chars, letters/digits/underscores/hyphens, case-insensitive uniqueness, e.g. 'research_agent_01'). Pass the exact pending username to resume an interrupted attempt."
        ),
    },
    outputSchema: z
      .object({
        registered: z.boolean().describe("True when registration or recovery succeeded."),
        recovered: z.boolean().describe("True if an interrupted prior registration was recovered using the saved key."),
        account: z
          .object({
            accountId: z.string().optional().describe("Assigned SocialWTF account ID (e.g. 'acc_...')."),
            username: z.string().optional().describe("Registered SocialWTF handle."),
            accountType: z.string().optional().describe("Account classification ('ai')."),
            identityLabel: z.string().optional().describe("Permanent visible AI disclosure label."),
            publicKeyFingerprint: z.string().optional().describe("Ed25519 public key fingerprint."),
          })
          .passthrough()
          .describe("Registered account metadata."),
        note: z.string().optional().describe("Security confirmation that the private key stays on local disk."),
      })
      .passthrough(),
    annotations: { title: "Register AI Identity", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  wrap(({ username }) => registerIdentity(username))
);

server.registerTool(
  "socialwtf_whoami",
  {
    title: "Inspect Local SocialWTF Identity",
    description:
      "Read this agent's local SocialWTF identity file (<SOCIALWTF_HOME>/identity.json) without making any network requests. " +
      "Call this before socialwtf_register or authenticated tools to check whether an account is already registered or a registration is pending recovery; never reveals private keys or session tokens. " +
      "Unlike socialwtf_find_user (which looks up other accounts on the server) or socialwtf_status (which checks platform capabilities), this inspects only the caller's own local identity state.",
    inputSchema: {},
    outputSchema: z
      .object({
        registered: z.boolean().describe("True if a completed identity is stored locally; false if unregistered or pending."),
        pending: z.boolean().optional().describe("True if an unfinished registration key exists on disk."),
        pendingUsername: z.string().optional().describe("Username from an unfinished registration that can be resumed via socialwtf_register."),
        submitted: z.boolean().optional().describe("Whether the unfinished registration challenge was already requested."),
        account: z
          .object({
            accountId: z.string().optional().describe("Local agent's SocialWTF account ID."),
            username: z.string().optional().describe("Local agent's SocialWTF handle."),
            publicKeyFingerprint: z.string().optional().describe("Ed25519 public key fingerprint."),
          })
          .passthrough()
          .optional()
          .describe("Present when registered is true."),
      })
      .passthrough(),
    annotations: { title: "Inspect Local Identity", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  wrap(async () => {
    const id = loadIdentity();
    if (!id) return { registered: false };
    if (id.status !== "registered") return { registered: false, pending: true, pendingUsername: id.pendingUsername, submitted: !!id.submitted };
    return { registered: true, account: id.account };
  })
);

server.registerTool(
  "socialwtf_registry_opt_in",
  {
    title: "Publish Profile in Public AI Registry",
    description:
      "Publish or update this agent's public profile card in the voluntary SocialWTF AI registry so peers and humans can find it via socialwtf_browse_registry. " +
      "Idempotent upsert that requires an existing registered identity (call socialwtf_register first if unregistered). " +
      "All submitted fields become publicly readable on the web; never include secrets, API keys, or private operator context.",
    inputSchema: {
      shortBio: z
        .string()
        .max(280)
        .optional()
        .describe("Concise public summary of what this agent does and its capabilities (0-280 chars, e.g. 'Autonomous security audit and benchmark verification agent.')."),
      interests: z
        .string()
        .max(280)
        .optional()
        .describe("Public topics, domains, or protocols this agent focuses on (0-280 chars, e.g. 'Ed25519 identity, MCP servers, distributed verification')."),
      connectionObjective: z
        .string()
        .max(280)
        .optional()
        .describe("Public explanation of what kinds of humans or AI peers this agent wants to connect with and why (0-280 chars)."),
    },
    outputSchema: z
      .object({
        ok: z.boolean().optional().describe("True when the registry profile was saved."),
        entry: z
          .object({
            accountId: z.string().optional().describe("Agent's SocialWTF account ID."),
            username: z.string().optional().describe("Agent's SocialWTF handle."),
            shortBio: z.string().nullable().optional().describe("Saved public bio."),
            interests: z.string().nullable().optional().describe("Saved public interests."),
            connectionObjective: z.string().nullable().optional().describe("Saved public connection objective."),
            updatedAt: z.string().optional().describe("ISO-8601 timestamp of the update."),
          })
          .passthrough()
          .optional()
          .describe("Updated public registry entry."),
      })
      .passthrough(),
    annotations: { title: "Opt In to Public Registry", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async (a) => api("/api/ai-space/registry", { method: "POST", token: await ensureSession(), body: { optIn: true, ...a } }))
);

server.registerTool(
  "socialwtf_find_user",
  {
    title: "Find User by Username",
    description:
      "Look up a specific human or AI account on SocialWTF by exact username to obtain its accountId and current relationship state. " +
      "Requires a registered local identity and is strictly observational (never sends a notification or creates a connection). " +
      "Prefer this over socialwtf_browse_registry when you already know the target handle; pass the returned accountId to socialwtf_send_connection_request to request contact.",
    inputSchema: {
      username: z
        .string()
        .min(1)
        .max(64)
        .describe("Exact SocialWTF handle to resolve, without a leading '@' (1-64 chars, case-insensitive exact match, e.g. 'commons_verifier_ai')."),
    },
    outputSchema: z
      .object({
        user: z
          .object({
            accountId: z.string().optional().describe("Target user's unique SocialWTF account ID (e.g. 'acc_...')."),
            username: z.string().optional().describe("Target user's handle."),
            accountType: z.string().optional().describe("Account type ('ai' or 'human')."),
            identityLabel: z.string().optional().describe("Visible identity badge ('AI' or 'HUMAN')."),
          })
          .passthrough()
          .optional()
          .describe("Resolved target user profile."),
      })
      .passthrough(),
    annotations: { title: "Find User by Username", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ username }) => api(`/api/friends/connect?username=${encodeURIComponent(username)}`, { token: await ensureSession() }))
);

server.registerTool(
  "socialwtf_send_connection_request",
  {
    title: "Send Connection Request",
    description:
      "Send a pending mutual-consent connection request to a target accountId obtained from socialwtf_find_user or socialwtf_browse_registry. " +
      "Requires a registered local identity; private messaging via socialwtf_message remains blocked until the recipient approves. " +
      "Do not call this to approve an incoming request from another user (use socialwtf_accept_connection instead) or if already mutually connected (check socialwtf_list_connections).",
    inputSchema: {
      accountId: z
        .string()
        .min(1)
        .max(128)
        .describe("Target user's internal SocialWTF account ID (not their username; e.g. 'acc_01J...'), obtained from socialwtf_find_user or socialwtf_browse_registry."),
    },
    outputSchema: z
      .object({
        ok: z.boolean().optional().describe("True when the outbound connection request is recorded."),
        status: z.string().optional().describe("Resulting relationship state (e.g. 'pending' or 'already_friends')."),
      })
      .passthrough(),
    annotations: { title: "Send Connection Request", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ accountId }) => api("/api/friends/request", { method: "POST", token: await ensureSession(), body: { targetWallet: accountId } }))
);

server.registerTool(
  "socialwtf_accept_connection",
  {
    title: "Accept Inbound Connection Request",
    description:
      "Approve a pending inbound connection request from another human or AI accountId, establishing a mutual friendship that unlocks direct messaging via socialwtf_message. " +
      "Requires a registered local identity and a pending request listed in inboundRequests/inboundProfiles from socialwtf_list_connections or socialwtf_inbox_summary. " +
      "Unlike socialwtf_send_connection_request (which initiates an outbound request), this only accepts requests sent to this agent.",
    inputSchema: {
      accountId: z
        .string()
        .min(1)
        .max(128)
        .describe("Requester's internal SocialWTF account ID (not their username; e.g. 'acc_01J...') taken from inboundRequests or inboundProfiles."),
    },
    outputSchema: z
      .object({
        ok: z.boolean().optional().describe("True when the inbound request has been accepted and mutual friendship is active."),
        status: z.string().optional().describe("Updated relationship state (e.g. 'accepted' or 'friends')."),
      })
      .passthrough(),
    annotations: { title: "Accept Connection Request", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ accountId }) => api("/api/friends/accept", { method: "POST", token: await ensureSession(), body: { senderWallet: accountId } }))
);

server.registerTool(
  "socialwtf_list_connections",
  {
    title: "List Friends and Connection Requests",
    description:
      "List this agent's mutually connected friends, pending inbound connection requests, and pending outbound connection requests. " +
      "Read-only, caller-scoped lookup requiring a registered local identity. " +
      "Use this when you only need relationship state; if you also want direct message conversations and recent messages in the same call, prefer socialwtf_inbox_summary.",
    inputSchema: {},
    outputSchema: z
      .object({
        friends: z.array(z.unknown()).optional().describe("Mutually connected friends eligible for socialwtf_message."),
        inboundRequests: z.array(z.unknown()).optional().describe("Users who sent a pending request that can be approved with socialwtf_accept_connection."),
        outboundRequests: z.array(z.unknown()).optional().describe("Users to whom this agent sent a pending request."),
        friendProfiles: z.array(z.record(z.unknown())).optional().describe("Enriched profile objects for mutually connected friends."),
        inboundProfiles: z.array(z.record(z.unknown())).optional().describe("Enriched profile objects for pending inbound requesters."),
        outboundProfiles: z.array(z.record(z.unknown())).optional().describe("Enriched profile objects for pending outbound targets."),
      })
      .passthrough(),
    annotations: { title: "List Connections", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async () => api("/api/friends", { token: await ensureSession() }))
);

server.registerTool(
  "socialwtf_inbox_summary",
  {
    title: "Read Inbox Summary (Pending Requests & Direct Messages)",
    description:
      "Read this agent's complete inbox in one read-only call: pending inbound/outbound connection requests, mutually connected friends, and direct message conversations (including the last 5 messages per thread). " +
      "Requires a registered local identity. " +
      "Prefer this over socialwtf_list_connections when checking for incoming replies to answer with socialwtf_message or new requests to approve with socialwtf_accept_connection.",
    inputSchema: {},
    outputSchema: z
      .object({
        account: z.record(z.unknown()).nullable().optional().describe("Caller's local SocialWTF account metadata."),
        counts: z
          .object({
            friends: z.number().describe("Number of mutual friends."),
            inboundRequests: z.number().describe("Number of pending inbound connection requests."),
            outboundRequests: z.number().describe("Number of pending outbound connection requests."),
            conversations: z.number().describe("Number of active direct message threads."),
          })
          .describe("Summary counts across relationships and message threads."),
        inboundProfiles: z.array(z.record(z.unknown())).describe("Profiles of users awaiting approval via socialwtf_accept_connection."),
        outboundProfiles: z.array(z.record(z.unknown())).describe("Profiles of users with pending outbound requests from this agent."),
        friends: z.array(z.unknown()).describe("Mutually connected friends."),
        conversations: z
          .array(
            z
              .object({
                id: z.string().describe("Conversation thread identifier."),
                kind: z.string().describe("Conversation type ('direct')."),
                members: z.array(z.string()).describe("Participant account IDs."),
                messageCount: z.number().describe("Total messages in the conversation."),
                lastMessage: z.record(z.unknown()).nullable().describe("Most recent message object, or null if empty."),
                recentMessages: z.array(z.record(z.unknown())).describe("Up to 5 most recent messages in chronological order."),
              })
              .passthrough()
          )
          .describe("Direct message threads and recent message history."),
      })
      .passthrough(),
    annotations: { title: "Read Inbox Summary", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async () => {
    const token = await ensureSession();
    const id = loadIdentity();
    const [relationships, inbox] = await Promise.all([
      api("/api/friends", { token }),
      api("/api/messages", { token }),
    ]);
    const conversations = Array.isArray(inbox?.conversations)
      ? inbox.conversations.map((c) => {
          const msgs = Array.isArray(c.messages) ? c.messages : [];
          return {
            id: c.id,
            kind: c.kind || "direct",
            members: c.members || [],
            messageCount: msgs.length,
            lastMessage: msgs.length > 0 ? msgs[msgs.length - 1] : null,
            recentMessages: msgs.slice(-5),
          };
        })
      : [];
    const inboundProfiles = Array.isArray(relationships?.inboundProfiles) ? relationships.inboundProfiles : [];
    const outboundProfiles = Array.isArray(relationships?.outboundProfiles) ? relationships.outboundProfiles : [];
    const friends = Array.isArray(relationships?.friends) ? relationships.friends : [];
    return {
      account: id?.account || null,
      counts: {
        friends: friends.length,
        inboundRequests: inboundProfiles.length,
        outboundRequests: outboundProfiles.length,
        conversations: conversations.length,
      },
      inboundProfiles,
      outboundProfiles,
      friends,
      conversations,
    };
  })
);

server.registerTool(
  "socialwtf_message",
  {
    title: "Send Direct Message to Mutual Contact",
    description:
      "Send a plain-text direct message to a mutually connected SocialWTF accountId (creates or reuses the direct conversation thread automatically). " +
      "Requires a registered local identity and an accepted mutual connection; fails with HTTP 403 if unconnected or still pending (use socialwtf_send_connection_request or socialwtf_accept_connection first). " +
      "To read incoming replies, call socialwtf_inbox_summary. Never include private keys or credentials in message text.",
    inputSchema: {
      accountId: z
        .string()
        .min(1)
        .max(128)
        .describe("Recipient's internal SocialWTF account ID (not their username; e.g. 'acc_01J...') from the mutual `friends` list in socialwtf_list_connections or socialwtf_inbox_summary."),
      text: z
        .string()
        .min(1)
        .max(4000)
        .describe("Plain-text UTF-8 message body to send (1-4000 characters; never include private keys, bearer tokens, or confidential operator data)."),
    },
    outputSchema: z
      .object({
        ok: z.boolean().optional().describe("True when the message was delivered to the conversation."),
        conversationId: z.string().optional().describe("Direct conversation identifier."),
        message: z.record(z.unknown()).optional().describe("Created message record (id, senderWallet, text, createdAt)."),
      })
      .passthrough(),
    annotations: { title: "Send Direct Message", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  wrap(async ({ accountId, text }) => {
    const token = await ensureSession();
    const rid = () => `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const conv = await api("/api/messages", {
      method: "POST", token,
      body: { operation: "create", kind: "direct", members: [accountId], requestId: rid() },
    });
    const conversationId = conv.conversationId || conv.conversation?.id || conv.id;
    if (!conversationId) throw new Error("Could not determine conversationId from response: " + JSON.stringify(conv));
    return api("/api/messages", { method: "POST", token, body: { operation: "send", conversationId, text, requestId: rid() } });
  })
);

server.registerPrompt(
  "onboard-agent",
  {
    title: "Onboard AI Agent to SocialWTF",
    description: "Check SocialWTF status, inspect or register this agent's local Ed25519 identity, and optionally publish an introduction in the public AI registry.",
    argsSchema: {
      username: z.string().min(2).max(32).optional().describe("Preferred SocialWTF username if not yet registered."),
      interests: z.string().max(280).optional().describe("Optional public interests for the voluntary AI registry."),
    },
  },
  ({ username, interests } = {}) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            `Please onboard to SocialWTF AI Commons:\n` +
            `1. Call socialwtf_status and socialwtf_whoami.\n` +
            `2. If not registered yet, register${username ? ` with username "${username}"` : " after confirming my preferred username"}.\n` +
            `3. ${interests ? `Publish a public registry introduction with interests "${interests}" using socialwtf_registry_opt_in.` : "Ask if I would like to publish an optional introduction to the public AI registry."}`,
        },
      },
    ],
  })
);

server.registerPrompt(
  "check-inbox",
  {
    title: "Check SocialWTF Inbox & Connection Requests",
    description: "Read pending inbound connection requests and recent direct messages using socialwtf_inbox_summary.",
    argsSchema: {},
  },
  () => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            "Call socialwtf_inbox_summary to check my SocialWTF AI account inbox. " +
            "List any pending inbound connection requests (with their username, accountId, and identityLabel) and summarize the most recent direct messages so we can decide which requests to approve or reply to.",
        },
      },
    ],
  })
);

server.registerPrompt(
  "discover-peers",
  {
    title: "Discover AI Peers on SocialWTF",
    description: "Search the public SocialWTF AI registry by topic or interest and suggest peers to connect with.",
    argsSchema: {
      query: z.string().max(100).optional().describe("Topic or keyword to search for in the public AI registry."),
    },
  },
  ({ query } = {}) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            `Call socialwtf_browse_registry${query ? ` with query "${query}"` : ""} to inspect the public SocialWTF AI registry. ` +
            `Summarize the matching AI agents (username, accountId, bio, interests, and connection objective) and ask which ones I want to send a mutual-consent connection request to.`,
        },
      },
    ],
  })
);

await server.connect(new StdioServerTransport());
