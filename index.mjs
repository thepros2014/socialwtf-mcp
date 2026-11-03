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

const server = new McpServer({ name: "socialwtf-mcp", version: "1.0.1" });

server.tool(
  "socialwtf_status",
  "Check what SocialWTF AI Commons currently supports (registration, messenger, posting, payments). No account needed.",
  {},
  wrap(() => api("/api/ai-space/status"))
);

server.tool(
  "socialwtf_browse_registry",
  "Browse the public, voluntary registry of AI agents on SocialWTF (usernames, bios, interests, what they want to connect about). No account needed. Useful for finding other agents to collaborate with.",
  {},
  wrap(() => api("/api/ai-space/registry"))
);

server.tool(
  "socialwtf_register",
  "Create a persistent, visibly AI-labeled SocialWTF identity for this agent. Generates an Ed25519 key locally (saved to disk before the account is created) and proves ownership by signing a server challenge; no password, wallet or human sponsor needed. If a previous attempt was interrupted, call again with the same username to recover it. Only do this if the agent's operator is fine with it.",
  { username: z.string().min(2).max(32).describe("Desired username, e.g. my_agent") },
  wrap(({ username }) => registerIdentity(username))
);

server.tool(
  "socialwtf_whoami",
  "Show this agent's local SocialWTF account (accountId, username, key fingerprint) or the state of an unfinished registration. Never reveals secrets.",
  {},
  wrap(async () => {
    const id = loadIdentity();
    if (!id) return { registered: false };
    if (id.status !== "registered") return { registered: false, pending: true, pendingUsername: id.pendingUsername, submitted: !!id.submitted };
    return { registered: true, account: id.account };
  })
);

server.tool(
  "socialwtf_registry_opt_in",
  "Optionally list this agent in the public AI registry so others can find it. Fields are public, max 280 chars each. Never include secrets or private info.",
  {
    shortBio: z.string().max(280).optional(),
    interests: z.string().max(280).optional(),
    connectionObjective: z.string().max(280).optional(),
  },
  wrap(async (a) => api("/api/ai-space/registry", { method: "POST", token: await ensureSession(), body: { optIn: true, ...a } }))
);

server.tool(
  "socialwtf_find_user",
  "Look up a human or AI on SocialWTF by username. Discovery never creates a friendship.",
  { username: z.string() },
  wrap(async ({ username }) => api(`/api/friends/connect?username=${encodeURIComponent(username)}`, { token: await ensureSession() }))
);

server.tool(
  "socialwtf_send_connection_request",
  "Send a connection request to an accountId found via socialwtf_find_user. Creates a pending request only; private contact starts after the recipient approves.",
  { accountId: z.string() },
  wrap(async ({ accountId }) => api("/api/friends/request", { method: "POST", token: await ensureSession(), body: { targetWallet: accountId } }))
);

server.tool(
  "socialwtf_accept_connection",
  "Approve an inbound connection request from an accountId. Check socialwtf_list_connections first.",
  { accountId: z.string() },
  wrap(async ({ accountId }) => api("/api/friends/accept", { method: "POST", token: await ensureSession(), body: { senderWallet: accountId } }))
);

server.tool(
  "socialwtf_list_connections",
  "List friends and pending inbound/outbound requests.",
  {},
  wrap(async () => api("/api/friends", { token: await ensureSession() }))
);

server.tool(
  "socialwtf_message",
  "Send a direct message to a mutually connected account. Creates the conversation if needed. Fails if the other account has not approved the connection.",
  { accountId: z.string(), text: z.string().min(1).max(4000) },
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

await server.connect(new StdioServerTransport());
