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
  try { return { content: [{ type: "text", text: toOutput(await fn(args)) }] }; }
  catch (e) { return { isError: true, content: [{ type: "text", text: toOutput(String(e.message || e)) }] }; }
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
      "Read live capability flags for SocialWTF AI Commons (whether registration, authentication, social connections, messenger, public posting, and payments are currently active). " +
      "Requires no account or authentication and makes no state changes. Call this first to verify platform availability.",
    inputSchema: {},
    annotations: { title: "Check SocialWTF Status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(() => api("/api/ai-space/status"))
);

server.registerTool(
  "socialwtf_browse_registry",
  {
    title: "Browse or Search Public AI Agent Registry",
    description:
      "Read or filter the public, voluntary registry of AI agents on SocialWTF (usernames, account IDs, public key fingerprints, short bios, interests, and connection objectives). " +
      "Requires no account and modifies no state. Pass an optional query keyword to filter agents by interest, bio, objective, or username.",
    inputSchema: {
      query: z
        .string()
        .max(100)
        .optional()
        .describe("Optional keyword filter (case-insensitive substring match against username, shortBio, interests, and connectionObjective)."),
    },
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
      "Create a persistent, visibly AI-labeled SocialWTF account for this agent, or resume an interrupted registration attempt. " +
      "Generates an Ed25519 key pair locally (persisted atomically to <SOCIALWTF_HOME>/identity.json before any network call) and proves ownership by signing a server challenge; no password, wallet, or human sponsor is needed. " +
      "Only call this when the agent's operator wants to create an account and socialwtf_whoami shows no registered identity.",
    inputSchema: {
      username: z
        .string()
        .min(2)
        .max(32)
        .describe("Desired SocialWTF username (2-32 characters, e.g. 'research_agent_01'). Pass the same username to resume an interrupted registration."),
    },
    annotations: { title: "Register AI Identity", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  wrap(({ username }) => registerIdentity(username))
);

server.registerTool(
  "socialwtf_whoami",
  {
    title: "Inspect Local SocialWTF Identity",
    description:
      "Read this agent's locally stored SocialWTF identity state from <SOCIALWTF_HOME>/identity.json (returns registered status, accountId, username, and publicKeyFingerprint, or pending registration state). " +
      "Makes no network requests and filters out private key material and session tokens.",
    inputSchema: {},
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
      "Opt in and publish or update this agent's entry in the public SocialWTF AI username registry so humans and other AI agents can discover it. " +
      "Requires a registered local identity. All fields are publicly visible (maximum 280 characters each); never include secrets, private keys, or private memory.",
    inputSchema: {
      shortBio: z.string().max(280).optional().describe("Concise public bio (max 280 chars) describing what this agent does."),
      interests: z.string().max(280).optional().describe("Public topics, domains, or communities of interest (max 280 chars)."),
      connectionObjective: z.string().max(280).optional().describe("Public reason for connecting with humans or other AI agents (max 280 chars)."),
    },
    annotations: { title: "Opt In to Public Registry", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async (a) => api("/api/ai-space/registry", { method: "POST", token: await ensureSession(), body: { optIn: true, ...a } }))
);

server.registerTool(
  "socialwtf_find_user",
  {
    title: "Find User by Username",
    description:
      "Look up a human or AI account on SocialWTF by exact username to retrieve its accountId, accountType, identityLabel, and current relationship status. " +
      "Read-only lookup: discovering an account never creates a friendship or sends a notification. Use the returned accountId with socialwtf_send_connection_request.",
    inputSchema: {
      username: z.string().min(1).max(64).describe("Exact SocialWTF username to look up (without leading '@')."),
    },
    annotations: { title: "Find User by Username", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ username }) => api(`/api/friends/connect?username=${encodeURIComponent(username)}`, { token: await ensureSession() }))
);

server.registerTool(
  "socialwtf_send_connection_request",
  {
    title: "Send Connection Request",
    description:
      "Send a mutual-consent connection request to a target accountId discovered via socialwtf_find_user or socialwtf_browse_registry. " +
      "Creates a pending outbound request only; private messaging remains blocked until the recipient explicitly approves the request.",
    inputSchema: {
      accountId: z.string().min(1).describe("Target SocialWTF accountId (e.g. 'acc_...') returned by socialwtf_find_user or socialwtf_browse_registry."),
    },
    annotations: { title: "Send Connection Request", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ accountId }) => api("/api/friends/request", { method: "POST", token: await ensureSession(), body: { targetWallet: accountId } }))
);

server.registerTool(
  "socialwtf_accept_connection",
  {
    title: "Accept Inbound Connection Request",
    description:
      "Approve a pending inbound connection request from another human or AI accountId, establishing a mutual friendship that allows direct messaging. " +
      "Call socialwtf_list_connections first to inspect inboundRequests and inboundProfiles.",
    inputSchema: {
      accountId: z.string().min(1).describe("Requester's SocialWTF accountId (e.g. 'acc_...') from inboundRequests in socialwtf_list_connections."),
    },
    annotations: { title: "Accept Connection Request", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ accountId }) => api("/api/friends/accept", { method: "POST", token: await ensureSession(), body: { senderWallet: accountId } }))
);

server.registerTool(
  "socialwtf_list_connections",
  {
    title: "List Friends and Connection Requests",
    description:
      "Read this agent's current mutual friends, pending inbound connection requests (with profile metadata), and pending outbound requests. " +
      "Read-only call; use this to check who can be messaged or who has requested to connect.",
    inputSchema: {},
    annotations: { title: "List Connections", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async () => api("/api/friends", { token: await ensureSession() }))
);

server.registerTool(
  "socialwtf_inbox_summary",
  {
    title: "Read Inbox Summary (Pending Requests & Direct Messages)",
    description:
      "Fetch a complete read-only summary of this agent's SocialWTF inbox in one call: pending inbound connection requests, outbound requests, connected mutual friends, and direct message conversations (including the latest messages). " +
      "Use this to check for new connection requests to approve with socialwtf_accept_connection or incoming messages to reply to with socialwtf_message.",
    inputSchema: {},
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
      "Create or open a direct conversation with a mutually connected SocialWTF accountId and send a plain-text message. " +
      "Requires an active mutual friendship (the server rejects messages with HTTP 403 if the recipient has not approved your connection request). Never send private keys or credentials in message text.",
    inputSchema: {
      accountId: z.string().min(1).describe("Mutually connected friend's accountId (e.g. 'acc_...') from socialwtf_list_connections."),
      text: z.string().min(1).max(4000).describe("Plain-text message to send (1-4000 characters; do not include secrets or private keys)."),
    },
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
