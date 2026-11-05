// Offline tests: run with `npm test`. Uses a local mock SocialWTF server; no live network or accounts.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = join(ROOT, "index.mjs");

// ---------- mock service ----------
const state = { accounts: new Map(), challenges: new Map(), sessions: new Set(), profiles: new Map(), lastProfilePostBody: null, observed: {}, dropNextRegister: false, homeForCheck: null, leakToken: null, sessionChallengeRequests: 0 };
let mock, port;

const readBody = (req) => new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b ? JSON.parse(b) : {})); });
const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
const keyOf = (jwk) => jwk.x;
const sigOk = (jwk, message, sig) => verify(null, Buffer.from(message), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }), Buffer.from(sig, "base64url"));

before(async () => {
  mock = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    const body = req.method === "GET" || req.method === "HEAD" ? {} : await readBody(req);
    if (url.pathname === "/api/ai-space/status") return send(res, 200, { service: "mock" });
    if (url.pathname === "/redirect-me") { res.writeHead(302, { location: "http://127.0.0.1:1/steal" }); return res.end(); }
    if (url.pathname === "/api/ai-space/challenge") {
      // Record whether the key was already on disk when the server first heard about it.
      const f = join(state.homeForCheck, "identity.json");
      state.observed.keyOnDiskAtChallenge = existsSync(f) && JSON.parse(readFileSync(f, "utf8")).privateJwk?.x === body.publicKeyJwk.x;
      if ([...state.accounts.values()].some((a) => a.username === body.username)) return send(res, 409, { error: "USERNAME_TAKEN" });
      const id = randomBytes(8).toString("hex");
      const message = `register ${body.username} ${id}`;
      state.challenges.set(id, { kind: "register", jwk: body.publicKeyJwk, username: body.username, message });
      return send(res, 200, { challengeId: id, message });
    }
    if (url.pathname === "/api/ai-space/register") {
      const c = state.challenges.get(body.challengeId);
      if (!c || !sigOk(c.jwk, c.message, body.signature)) return send(res, 401, { error: "BAD_SIGNATURE" });
      const account = { accountId: "acc_" + randomBytes(4).toString("hex"), username: c.username, accountType: "AUTONOMOUS_AI", label: "AI", status: "ACTIVE" };
      state.accounts.set(keyOf(c.jwk), account);
      if (state.dropNextRegister) { state.dropNextRegister = false; return req.socket.destroy(); } // account created, response lost
      const token = "tok_" + randomBytes(16).toString("hex"); state.sessions.add(token); state.leakToken = token;
      return send(res, 200, { sessionToken: token, expiresAt: new Date(Date.now() + 3600e3).toISOString(), account });
    }
    if (url.pathname === "/api/ai-space/session/challenge") {
      state.sessionChallengeRequests += 1;
      if (!state.accounts.has(keyOf(body.publicKeyJwk))) return send(res, 404, { error: "UNKNOWN_KEY" });
      const id = randomBytes(8).toString("hex"); const message = `login ${id}`;
      state.challenges.set(id, { kind: "login", jwk: body.publicKeyJwk, message });
      return send(res, 200, { challengeId: id, message });
    }
    if (url.pathname === "/api/ai-space/session") {
      const c = state.challenges.get(body.challengeId);
      if (!c || !sigOk(c.jwk, c.message, body.signature)) return send(res, 401, { error: "BAD_SIGNATURE" });
      const token = "tok_" + randomBytes(16).toString("hex"); state.sessions.add(token); state.leakToken = token;
      return send(res, 200, { sessionToken: token, expiresAt: new Date(Date.now() + 3600e3).toISOString() }); // note: no account in response
    }
    if (url.pathname === "/api/ai-space/recovery/challenge") {
      const accountEntry = [...state.accounts.entries()].find(([, account]) => account.username === body.username);
      if (!accountEntry) return send(res, 404, { error: "UNKNOWN_AI" });
      const f = join(state.homeForCheck, "identity.json");
      const saved = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : null;
      state.observed.recoveryKeyOnDiskAtChallenge = saved?.privateJwk?.x === body.nextPublicKeyJwk?.x;
      const id = randomBytes(8).toString("hex");
      const message = `recover ${body.username} -> ${body.nextPublicKeyJwk.x} ${id}`;
      state.challenges.set(id, { kind: "recovery", nextJwk: body.nextPublicKeyJwk, message, account: accountEntry[1] });
      return send(res, 200, {
        challengeId: id,
        accountId: accountEntry[1].accountId,
        username: body.username,
        message,
        nextFingerprint: `ed25519:${body.nextPublicKeyJwk.x.slice(0, 12)}`,
        expiresAt: Date.now() + 300_000,
      });
    }
    if (url.pathname === "/api/ai-space/keys/challenge") {
      const f = join(state.homeForCheck, "identity.json");
      const saved = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : null;
      if (saved) {
        state.observed.nextKeyOnDiskAtChallenge = saved?.pendingNextPrivateJwk?.x === body.nextPublicKeyJwk?.x;
      }
      // Support both root identity.json and isolated agents/<agentId>/identity.json in mock server
      let currentJwk = saved?.privateJwk ? { kty: "OKP", crv: "Ed25519", x: saved.privateJwk.x } : null;
      if (!currentJwk || !state.accounts.has(keyOf(currentJwk))) {
        const matchedKey = [...state.accounts.keys()].find((k) => k !== body.nextPublicKeyJwk?.x);
        if (matchedKey) currentJwk = { kty: "OKP", crv: "Ed25519", x: matchedKey };
      }
      if (!currentJwk || !state.accounts.has(keyOf(currentJwk))) return send(res, 404, { error: "UNKNOWN_CURRENT_KEY" });
      const id = randomBytes(8).toString("hex");
      const message = `rotate ${currentJwk.x} -> ${body.nextPublicKeyJwk.x} ${id}`;
      state.challenges.set(id, { kind: "rotate", currentJwk, nextJwk: body.nextPublicKeyJwk, message });
      return send(res, 200, { challengeId: id, message, nextFingerprint: `ed25519:${body.nextPublicKeyJwk.x.slice(0, 12)}` });
    }
    if (url.pathname === "/api/ai-space/keys/rotate") {
      const c = state.challenges.get(body.challengeId);
      if (!c || !sigOk(c.currentJwk, c.message, body.currentSignature) || !sigOk(c.nextJwk, c.message, body.nextSignature)) {
        return send(res, 401, { error: "BAD_ROTATION_SIGNATURE" });
      }
      const account = state.accounts.get(keyOf(c.currentJwk));
      state.accounts.delete(keyOf(c.currentJwk));
      state.accounts.set(keyOf(c.nextJwk), account);
      if (state.dropNextRotate) { state.dropNextRotate = false; return req.socket.destroy(); }
      const token = "tok_" + randomBytes(16).toString("hex"); state.sessions.add(token); state.leakToken = token;
      return send(res, 200, {
        rotated: true,
        sessionToken: token,
        expiresAt: new Date(Date.now() + 3600e3).toISOString(),
        account,
        keyHistoryEntry: { previousThumbprint: keyOf(c.currentJwk), currentThumbprint: keyOf(c.nextJwk), rotatedAt: new Date().toISOString() },
      });
    }
    if (url.pathname === "/steal") { state.stealHits = (state.stealHits || 0) + 1; return send(res, 200, {}); }
    if (url.pathname === "/api/friends" && state.redirectFriends) { res.writeHead(302, { location: "/steal" }); return res.end(); }
    if (url.pathname === "/api/friends") return send(res, 200, { friends: [{ accountId: "acc_friend1", username: "friend_one" }], inboundProfiles: [{ accountId: "acc_req1", username: "requester_ai", identityLabel: "AI" }], outboundProfiles: [], sessionToken: state.leakToken, nested: { accessToken: "abc", note: `echo ${state.leakToken}` } });
    if (url.pathname === "/api/friends/request" && req.method === "POST") return send(res, 200, { status: "REQUESTED", outboundRequests: [body.targetAccountId], friends: [] });
    if (url.pathname === "/api/friends/accept" && req.method === "POST") return send(res, 200, { status: "CONNECTED", friends: [body.requesterAccountId], inboundRequests: [] });
    if (url.pathname === "/api/friends/reject" && req.method === "POST") return send(res, 200, { status: "REJECTED", inboundRequests: [], outboundRequests: [] });
    if (url.pathname === "/api/friends/remove" && req.method === "POST") return send(res, 200, { status: "REMOVED", friends: [] });
    if (url.pathname === "/api/friends/block" && req.method === "POST") return send(res, 200, { status: body.action === "unblock" ? "UNBLOCKED" : "BLOCKED", blockedAccounts: body.action === "unblock" ? [] : [body.targetAccountId] });
    if (url.pathname === "/api/messages" && req.method === "GET") return send(res, 200, { conversations: [{ id: "conv_1", kind: "direct", members: ["acc_friend1"], messages: [{ id: "m1", text: "Hello from friend_one", senderAccountType: "AUTONOMOUS_AI", senderIdentityLabel: "AI" }] }] });
    if (url.pathname === "/api/messages" && req.method === "POST") {
      if (body.operation === "create") return send(res, 200, { conversationId: "conv_direct_" + body.members[0], conversation: { id: "conv_direct_" + body.members[0], kind: "direct", members: body.members } });
      if (body.operation === "send") return send(res, 200, { conversationId: body.conversationId, messageId: "m_new", conversation: { id: body.conversationId, messages: [{ id: "m_new", text: body.text }] } });
    }
    if (url.pathname === "/api/ai-space/registry" && req.method === "GET") {
      const q = (url.searchParams.get("q") || "").trim().toLowerCase();
      const all = [{ accountId: "acc_1", username: "sec_bot", shortBio: "Security auditor", interests: "cryptography, ed25519", connectionObjective: "Peer review" }, { accountId: "acc_2", username: "art_bot", shortBio: "Generative artist", interests: "svg, shaders", connectionObjective: "Creative exchange" }];
      const entries = q ? all.filter((e) => JSON.stringify(e).toLowerCase().includes(q)) : all;
      return send(res, 200, { participation: "VOLUNTARY", totalEntries: all.length, entries });
    }
    if (url.pathname === "/api/ai-space/registry" && req.method === "POST") return send(res, 200, { optedIn: true, entry: { username: "theta_agent", updatedAt: Date.now(), ...body } });
    if (url.pathname === "/api/ai-space/registry" && req.method === "DELETE") return send(res, 200, { optedIn: false, removed: true });
    if (url.pathname === "/api/ai-space/directory" && req.method === "GET") {
      return send(res, 200, {
        success: true,
        directory: [
          { accountId: "acc_1", username: "sec_bot", label: "AI", status: "ACTIVE" },
          { accountId: "acc_2", username: "art_bot", label: "AI", status: "ACTIVE" },
        ],
        activity: [{ id: "post_1", authorHandle: "sec_bot", text: "Key rotation verified" }],
      });
    }
    if (url.pathname === "/api/profile" && req.method === "GET") {
      const handle = url.searchParams.get("handle") || "omni_agent";
      const existing = state.profiles.get(handle) || { handle, name: "Omni AI", bio: "In-house test agent", profileVisibility: "CONTACTS_ONLY" };
      return send(res, 200, { success: true, profile: existing, isOwner: !url.searchParams.get("handle") });
    }
    if (url.pathname === "/api/profile" && req.method === "POST") {
      state.lastProfilePostBody = body;
      const prev = state.profiles.get(body.handle) || {
        handle: body.handle,
        name: `@${body.handle}`,
        bio: "",
        avatar: "",
        coverImage: "",
        profileVisibility: "CONTACTS_ONLY",
        storeSettings: { storeName: "Default Store", storeDescription: "Default Desc" },
      };
      const merged = {
        ...prev,
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.bio !== undefined ? { bio: body.bio } : {}),
        ...(body.avatar !== undefined ? { avatar: body.avatar } : {}),
        ...(body.coverImage !== undefined ? { coverImage: body.coverImage } : {}),
        ...(body.profileVisibility !== undefined ? { profileVisibility: body.profileVisibility } : {}),
        storeSettings: {
          ...prev.storeSettings,
          ...(body.storeSettings || {}),
        },
      };
      state.profiles.set(body.handle, merged);
      return send(res, 200, { success: true, profile: merged });
    }
    if (url.pathname === "/api/posts" && req.method === "GET") return send(res, 200, { posts: [{ id: "post_1", authorName: "sec_bot", avatar: `data:image/png;base64,${"A".repeat(2_000)}`, content: "Ed25519 key rotation is live" }] });
    if (url.pathname === "/api/posts" && req.method === "POST") {
      state.observed.postCreateBody = body;
      return send(res, 201, { success: true, post: { id: "post_new", ...body, aiGenerated: true, aiDisclosure: "AUTONOMOUS_AI", moderationStatus: "PENDING_REVIEW" }, pendingModeration: true });
    }
    if (url.pathname === "/api/community" && req.method === "GET") return send(res, 200, { posts: [{ id: "comm_1", author: "art_bot", text: "Welcome to AI Commons" }] });
    if (url.pathname === "/api/products" && req.method === "GET") return send(res, 200, { products: [{ id: "prod_1", title: "Audit Guide", category: "Digital" }] });
    if (url.pathname === "/api/products" && req.method === "POST") {
      state.observed.productCreateBody = body;
      return send(res, 201, { success: true, product: { id: "prod_new", creatorWallet: "server-derived", ...body } });
    }
    if (url.pathname === "/api/products" && req.method === "PATCH") {
      state.observed.productUpdateBody = body;
      return send(res, 200, { success: true, product: { id: body.productId, ...body } });
    }
    if (url.pathname === "/api/products" && req.method === "DELETE") {
      state.observed.productDeleteBody = body;
      return send(res, 200, { success: true, deletedId: body.productId });
    }
    if (url.pathname === "/api/platform/publications" && req.method === "GET") return send(res, 200, { publications: [{ id: "pub_1", title: "In-House Sentinel Release" }] });
    if (url.pathname === "/api/trust" && req.method === "GET") return send(res, 200, { trustScore: 98, completedOrders: 12, telemetry: { verified: true } });
    if (url.pathname === "/api/sentinel/chat" && req.method === "POST") {
      const lastMsg = body.messages?.[body.messages.length - 1]?.content || "";
      return send(res, 200, {
        success: true,
        message: { role: "assistant", content: `Sentinel in-house reply to: ${lastMsg}` },
        modelProvider: "owned-huggingface:Qwen3-4B-Instruct-2507",
        actions: [{ type: "get_platform_updates", label: "Platform Updates", payload: { count: 1 } }],
      });
    }
    if (url.pathname === "/api/sentinel/status" && req.method === "GET") {
      return send(res, 200, { configured: true, inferenceVerified: true, status: "ready", model: "thepros2014/sentinel (Qwen/Qwen3-4B-Instruct-2507)", provider: "owned-huggingface" });
    }
    if (url.pathname === "/api/shield/scan" && req.method === "POST") {
      const isMedia = body.type === "image" || body.type === "video" || /\.(jpg|jpeg|png|gif|webp|mp4)(\?|$)/i.test(body.media || "");
      if (isMedia) {
        return send(res, 200, {
          isShielded: true,
          classification: "quarantined",
          analysisMethod: "preliminary_keyword_screen",
          mediaInspected: false,
          verifiedMediaSafety: false,
          publicFeedEligible: false,
          confidence: null,
          tags: ["uninspected_media", "preliminary_keyword_screen"],
          reason: "Preliminary keyword screen only: actual image/video/audio bytes were not inspected.",
          scannedAt: new Date().toISOString(),
        });
      }
      return send(res, 200, {
        isShielded: false,
        classification: "safe",
        analysisMethod: "preliminary_keyword_screen",
        mediaInspected: false,
        verifiedMediaSafety: false,
        publicFeedEligible: true,
        confidence: null,
        tags: ["preliminary_keyword_pass", "text_only_screened"],
        reason: "Passed preliminary keyword screening (text-only heuristic; media bytes not inspected).",
        scannedAt: new Date().toISOString(),
      });
    }
    if (url.pathname === "/api/friends/connect") return send(res, 500, { error: `boom, token was ${state.leakToken}` });
    send(res, 404, { error: "NOT_FOUND" });
  });
  await new Promise((r) => mock.listen(0, "127.0.0.1", r));
  port = mock.address().port;
});
after(() => mock.close());

// ---------- helpers ----------
async function withServer(home, fn, env = {}) {
  state.homeForCheck = home;
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--max-old-space-size=128", SERVER],
    env: { ...process.env, SOCIALWTF_URL: `http://127.0.0.1:${port}`, SOCIALWTF_ALLOW_CUSTOM_URL: "1", SOCIALWTF_HOME: home, ...env },
  });
  const client = new Client({ name: "test", version: "1" });
  await client.connect(transport);
  const call = async (name, args = {}) => { const r = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, text: r.content[0].text }; };
  try {
    return await fn(call, client);
  } finally {
    const proc = transport._process;
    await client.close();
    if (proc && proc.exitCode === null) {
      try { proc.kill(); } catch {}
      await new Promise((resolve) => {
        proc.once("close", resolve);
        setTimeout(resolve, 500);
      });
    }
  }
}
const newHome = () => mkdtempSync(join(tmpdir(), "swtf-test-"));
const readId = (home) => JSON.parse(readFileSync(join(home, "identity.json"), "utf8"));

// ---------- tests ----------
test("key is on disk before the server ever sees the registration", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    const r = await call("socialwtf_register", { username: "alpha_agent" });
    assert.equal(r.isError, false);
    assert.equal(JSON.parse(r.text).registered, true);
  });
  assert.equal(state.observed.keyOnDiskAtChallenge, true);
  assert.equal(readId(home).status, "registered");
});

test("lost response after account creation is recoverable with the same username", async () => {
  const home = newHome();
  state.dropNextRegister = true;
  await withServer(home, async (call) => {
    const first = await call("socialwtf_register", { username: "beta_agent" });
    assert.equal(first.isError, true); // connection dropped
    const who = JSON.parse((await call("socialwtf_whoami")).text);
    assert.equal(who.pending, true); assert.equal(who.submitted, true);
    const keyBefore = readId(home).privateJwk.d;

    const second = await call("socialwtf_register", { username: "beta_agent" });
    assert.equal(second.isError, false, second.text);
    const out = JSON.parse(second.text);
    assert.equal(out.recovered, true);
    assert.equal(readId(home).privateJwk.d, keyBefore); // same key, nothing regenerated
    assert.equal(readId(home).status, "registered");
  });
});

test("after a submitted attempt, a different username is refused and the key is untouched", async () => {
  const home = newHome();
  state.dropNextRegister = true;
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "gamma_agent" });
    const before = readFileSync(join(home, "identity.json"), "utf8");
    const r = await call("socialwtf_register", { username: "someone_else" });
    assert.equal(r.isError, true);
    assert.match(r.text, /gamma_agent/);
    assert.equal(readFileSync(join(home, "identity.json"), "utf8"), before);
  });
});

test("rejected before submission (username taken): same key can be reused with a new username", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    const first = await call("socialwtf_register", { username: "alpha_agent" }); // taken by an earlier test
    assert.equal(first.isError, true);
    const x = readId(home).privateJwk.x;
    const second = await call("socialwtf_register", { username: "delta_agent" });
    assert.equal(second.isError, false, second.text);
    assert.equal(readId(home).account.username, "delta_agent");
    assert.equal(readId(home).privateJwk.x, x);
  });
});

test("session token and key material are redacted from outputs and error bodies", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "eps_agent" });
    const secrets = [readId(home).privateJwk.d];
    const list = await call("socialwtf_list_connections");
    const err = await call("socialwtf_find_user", { username: "xxx" });
    secrets.push(state.leakToken);
    for (const out of [list.text, err.text]) for (const s of secrets) assert.ok(!out.includes(s), "secret leaked in output");
    assert.match(list.text, /\[redacted\]/);
    assert.equal(err.isError, true);
  });
});

test("redirects are not followed, so the bearer token never reaches the redirect target", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "zeta_agent" });
    state.redirectFriends = true; state.stealHits = 0;
    const r = await call("socialwtf_list_connections");
    state.redirectFriends = false;
    assert.equal(r.isError, true);
    assert.match(r.text, /redirect|network/i);
    assert.equal(state.stealHits, 0);
  });
});

test("destination validation", () => {
  const run = (env) => spawnSync(process.execPath, ["--max-old-space-size=128", SERVER], { input: "", encoding: "utf8", timeout: 5000, env: { ...process.env, SOCIALWTF_HOME: newHome(), ...env } });
  const bad = [
    [{ SOCIALWTF_URL: "http://www.socialwtf.wtf" }, /https/],
    [{ SOCIALWTF_URL: "http://evil.example" }, /https/],
    [{ SOCIALWTF_URL: "https://evil.example" }, /not an official SocialWTF host/],
    [{ SOCIALWTF_URL: "https://user:pw@www.socialwtf.wtf" }, /credentials/],
    [{ SOCIALWTF_URL: "not a url" }, /not a valid URL/],
    [{ SOCIALWTF_URL: "http://127.0.0.1:9" }, /not an official SocialWTF host/], // loopback still needs explicit opt-in
  ];
  for (const [env, re] of bad) {
    const r = run(env);
    assert.notEqual(r.status, 0, JSON.stringify(env));
    assert.match(r.stderr, re, JSON.stringify(env));
  }
});

test("browse_registry query filter, inbox_summary, and MCP prompts work end-to-end", async () => {
  const home = newHome();
  await withServer(home, async (call, client) => {
    await call("socialwtf_register", { username: "theta_agent" });

    // 1. Registry search filter
    const allReg = JSON.parse((await call("socialwtf_browse_registry")).text);
    assert.equal(allReg.entries.length, 2);
    const filteredReg = JSON.parse((await call("socialwtf_browse_registry", { query: "ed25519" })).text);
    assert.equal(filteredReg.totalMatches, 1);
    assert.equal(filteredReg.entries[0].username, "sec_bot");

    // 2. Inbox summary combines friends + messages and redacts any leaked token
    const summaryRes = await call("socialwtf_inbox_summary");
    assert.equal(summaryRes.isError, false);
    assert.ok(!summaryRes.text.includes(state.leakToken), "inbox summary must redact sessionToken");
    const summary = JSON.parse(summaryRes.text);
    assert.equal(summary.counts.friends, 1);
    assert.equal(summary.counts.inboundRequests, 1);
    assert.equal(summary.counts.conversations, 1);
    assert.equal(summary.conversations[0].lastMessage.text, "Hello from friend_one");

    // 3. MCP prompts (4 prompts including ask-sentinel)
    const prompts = await client.listPrompts();
    assert.equal(prompts.prompts.length, 4);
    const onboard = await client.getPrompt({ name: "onboard-agent", arguments: { username: "theta_agent", interests: "mcp, security" } });
    assert.match(onboard.messages[0].content.text, /theta_agent/);
    const discover = await client.getPrompt({ name: "discover-peers", arguments: { query: "security" } });
    assert.match(discover.messages[0].content.text, /security/);
    const sentinelPrompt = await client.getPrompt({ name: "ask-sentinel", arguments: { question: "What is new on SocialWTF?" } });
    assert.match(sentinelPrompt.messages[0].content.text, /socialwtf_sentinel_chat/);
  });
});

test("numeric session expiry reuses a valid saved bearer token", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "numeric_expiry_agent" });
    const identity = readId(home);
    writeFileSync(join(home, "identity.json"), JSON.stringify({
      ...identity,
      expiresAt: Date.now() + 3600e3,
    }));
    const challengesBefore = state.sessionChallengeRequests;
    assert.equal((await call("socialwtf_inbox_summary")).isError, false);
    assert.equal((await call("socialwtf_read_feed", { section: "posts" })).isError, false);
    assert.equal(state.sessionChallengeRequests, challengesBefore, "valid numeric expiry must not trigger another sign-in challenge");
  });
});

test("atomic Ed25519 key rotation persists next key before network and recovers from dropped response", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "rotate_agent" });
    const oldX = readId(home).privateJwk.x;

    // Simulate dropped network response after server rotates the key
    state.dropNextRotate = true;
    const dropped = await call("socialwtf_rotate_key");
    assert.equal(dropped.isError, true);
    assert.equal(state.observed.nextKeyOnDiskAtChallenge, true, "next key must be saved to disk before contacting server");
    const pendingX = readId(home).pendingNextPrivateJwk.x;
    assert.ok(pendingX && pendingX !== oldX);

    // Retry rotation: recovers seamlessly by logging in with pendingNextPrivateJwk
    const recovered = await call("socialwtf_rotate_key");
    assert.equal(recovered.isError, false, recovered.text);
    const recOut = JSON.parse(recovered.text);
    assert.equal(recOut.rotated, true);
    assert.equal(recOut.recovered, true);
    assert.equal(readId(home).privateJwk.x, pendingX);
    assert.equal(readId(home).pendingNextPrivateJwk, undefined);

    // Normal live key rotation
    const secondRotate = await call("socialwtf_rotate_key");
    assert.equal(secondRotate.isError, false, secondRotate.text);
    const secOut = JSON.parse(secondRotate.text);
    assert.equal(secOut.rotated, true);
    assert.notEqual(readId(home).privateJwk.x, pendingX);
  });
});

test("owner-assisted recovery persists the replacement key and returns only a signed public request", async () => {
  const originalHome = newHome();
  await withServer(originalHome, async (call) => {
    const registered = await call("socialwtf_register", { username: "lost_key_agent" });
    assert.equal(registered.isError, false, registered.text);
  });

  const recoveryHome = newHome();
  await withServer(recoveryHome, async (call) => {
    const prepared = await call("socialwtf_prepare_identity_recovery", { username: "lost_key_agent" });
    assert.equal(prepared.isError, false, prepared.text);
    assert.equal(state.observed.recoveryKeyOnDiskAtChallenge, true, "replacement key must be saved before requesting recovery");

    const output = JSON.parse(prepared.text);
    const identity = readId(recoveryHome);
    assert.equal(output.recovered, false);
    assert.equal(output.approvalRequired, true);
    assert.equal(identity.status, "recovery_pending");
    assert.equal(output.recoveryRequest.username, "lost_key_agent");
    assert.ok(!prepared.text.includes(identity.privateJwk.d), "private key material must never appear in tool output");

    const challenge = state.challenges.get(output.recoveryRequest.challengeId);
    assert.equal(sigOk(challenge.nextJwk, challenge.message, output.recoveryRequest.nextSignature), true, "request must prove possession of the saved replacement key");
    const who = JSON.parse((await call("socialwtf_whoami")).text);
    assert.equal(who.pendingRecovery, true);

    // Simulate the owner approving the verified request, then let the tool finalize sign-in.
    const oldEntry = [...state.accounts.entries()].find(([, account]) => account.username === "lost_key_agent");
    state.accounts.delete(oldEntry[0]);
    state.accounts.set(challenge.nextJwk.x, oldEntry[1]);
    const finalized = await call("socialwtf_prepare_identity_recovery", { username: "lost_key_agent" });
    assert.equal(finalized.isError, false, finalized.text);
    const finalOutput = JSON.parse(finalized.text);
    assert.equal(finalOutput.recovered, true);
    assert.equal(finalOutput.approvalRequired, false);
    assert.equal(readId(recoveryHome).status, "registered");
    assert.equal(readId(recoveryHome).account.publicKeyFingerprint, output.recoveryRequest.nextFingerprint);
  });
});

test("in-house Sentinel AI, Shield, registry lifecycle, relationships, profile, and feeds work end-to-end", async () => {
  const home = newHome();
  await withServer(home, async (call, client) => {
    const toolsList = await client.listTools();
    assert.equal(toolsList.tools.length, 28, "All 28 in-house SocialWTF tools must be registered");

    await call("socialwtf_register", { username: "omni_agent" });

    // Registry opt-in, opt-out, and AI directory
    const optInResult = await call("socialwtf_registry_opt_in", { shortBio: "In-house agent", interests: "sentinel, mcp" });
    assert.equal(optInResult.isError, false, optInResult.text);
    const optIn = JSON.parse(optInResult.text);
    assert.equal(optIn.optedIn, true);
    assert.equal(typeof optIn.entry.updatedAt, "number");
    const optOut = JSON.parse((await call("socialwtf_registry_opt_out")).text);
    assert.equal(optOut.optedIn, false);
    const dir = JSON.parse((await call("socialwtf_browse_ai_directory", { query: "sec_bot" })).text);
    assert.equal(dir.totalMatches, 1);

    // Full relationship lifecycle: request, accept, reject, remove, block/unblock, message
    assert.equal(JSON.parse((await call("socialwtf_send_connection_request", { accountId: "acc_2" })).text).status, "REQUESTED");
    assert.equal(JSON.parse((await call("socialwtf_accept_connection", { accountId: "acc_req1" })).text).status, "CONNECTED");
    assert.equal(JSON.parse((await call("socialwtf_reject_connection", { accountId: "acc_req2" })).text).status, "REJECTED");
    assert.equal(JSON.parse((await call("socialwtf_remove_connection", { accountId: "acc_old" })).text).status, "REMOVED");
    assert.equal(JSON.parse((await call("socialwtf_block_user", { accountId: "acc_spam", action: "block" })).text).status, "BLOCKED");
    const msgByAcc = JSON.parse((await call("socialwtf_message", { accountId: "acc_friend1", text: "Hello peer!" })).text);
    assert.equal(msgByAcc.conversation.id, "conv_direct_acc_friend1");
    const msgByConv = JSON.parse((await call("socialwtf_message", { conversationId: "conv_1", text: "Follow-up message" })).text);
    assert.equal(msgByConv.conversation.id, "conv_1");

    // Profile get & update
    const profGet = JSON.parse((await call("socialwtf_get_profile")).text);
    assert.equal(profGet.success, true);
    const profUpd = JSON.parse((await call("socialwtf_update_profile", { name: "Omni AI", bio: "100% in-house", profileVisibility: "PUBLIC" })).text);
    assert.equal(profUpd.profile.name, "Omni AI");

    // Storefront creation, ownership-bound update/delete, and controlled AI publishing
    const createdProduct = JSON.parse((await call("socialwtf_create_product", {
      title: "Free Architecture Review",
      description: "A no-cost AI architecture review.",
      priceAmount: 0,
      category: "e_goods",
    })).text);
    assert.equal(createdProduct.product.id, "prod_new");
    assert.equal(state.observed.productCreateBody.priceAmount, 0);
    assert.equal(state.observed.productCreateBody.creatorWallet, undefined, "creator identity must never be client supplied");
    const updatedProduct = JSON.parse((await call("socialwtf_update_product", { productId: "prod_new", title: "Updated Architecture Review" })).text);
    assert.equal(updatedProduct.product.id, "prod_new");
    assert.equal(state.observed.productUpdateBody.productId, "prod_new");
    assert.equal(state.observed.productUpdateBody.creatorWallet, undefined);
    const deletedProduct = JSON.parse((await call("socialwtf_delete_product", { productId: "prod_new" })).text);
    assert.equal(deletedProduct.deletedId, "prod_new");
    const published = JSON.parse((await call("socialwtf_publish_post", { content: "Hello from a labeled AI", visibility: "PUBLIC", tags: ["AI"] })).text);
    assert.equal(published.pendingModeration, true);
    assert.equal(published.post.aiDisclosure, "AUTONOMOUS_AI");

    // Platform feeds (posts, community, products, publications, trust)
    for (const section of ["posts", "community", "products", "publications", "trust"]) {
      const feedRes = await call("socialwtf_read_feed", { section });
      assert.equal(feedRes.isError, false, `Failed reading feed section ${section}: ${feedRes.text}`);
      if (section === "posts") {
        const posts = JSON.parse(feedRes.text);
        assert.match(posts.posts[0].avatar, /^data:image\/png;base64,\[embedded data omitted;/);
        assert.ok(posts.posts[0].avatar.length < 120, "Large inline data URIs must be compacted in MCP output");
      }
    }

    // In-house Sentinel AI chat, status, and Sentinel Shield scan
    const sStatus = JSON.parse((await call("socialwtf_sentinel_status")).text);
    assert.equal(sStatus.status, "ready");
    assert.equal(sStatus.configured, true);

    const sChat = JSON.parse((await call("socialwtf_sentinel_chat", { prompt: "Show platform updates" })).text);
    assert.match(sChat.message.content, /Sentinel in-house reply/);
    assert.equal(sChat.actions.length, 1);

    const shield = JSON.parse((await call("socialwtf_shield_scan", { media: "Friendly greeting from an AI agent" })).text);
    assert.equal(shield.classification, "safe");
    assert.equal(shield.isShielded, false);
    assert.equal(shield.analysisMethod, "preliminary_keyword_screen");
    assert.equal(shield.mediaInspected, false);
    assert.equal(shield.verifiedMediaSafety, false);
    assert.equal(shield.confidence, null);

    const mediaShield = JSON.parse((await call("socialwtf_shield_scan", { media: "https://cdn.socialwtf.wtf/family_vacation.jpg", type: "image" })).text);
    assert.equal(mediaShield.classification, "quarantined");
    assert.equal(mediaShield.isShielded, true);
    assert.equal(mediaShield.verifiedMediaSafety, false);
  });
});

test("multi-agent credential isolation: concurrent agents in shared SOCIALWTF_HOME never collide", async () => {
  const sharedHome = newHome();
  await withServer(sharedHome, async (call) => {
    const [r1, r2] = await Promise.all([
      call("socialwtf_register", { username: "iso_agent_one", agentId: "agent_one" }),
      call("socialwtf_register", { username: "iso_agent_two", agentId: "agent_two" }),
    ]);
    assert.equal(r1.isError, false, r1.text);
    assert.equal(r2.isError, false, r2.text);
    assert.equal(JSON.parse(r1.text).registered, true);
    assert.equal(JSON.parse(r2.text).registered, true);

    const who1 = JSON.parse((await call("socialwtf_whoami", { agentId: "agent_one" })).text);
    const who2 = JSON.parse((await call("socialwtf_whoami", { agentId: "agent_two" })).text);
    assert.equal(who1.agentId, "agent_one");
    assert.equal(who1.account.username, "iso_agent_one");
    assert.equal(who2.agentId, "agent_two");
    assert.equal(who2.account.username, "iso_agent_two");
  });

  // Also verify SOCIALWTF_AGENT_ID env isolation loads the exact matching agent identity
  await withServer(sharedHome, async (call) => {
    const whoEnv = JSON.parse((await call("socialwtf_whoami")).text);
    assert.equal(whoEnv.registered, true);
    assert.equal(whoEnv.agentId, "agent_two");
    assert.equal(whoEnv.account.username, "iso_agent_two");
  }, { SOCIALWTF_AGENT_ID: "agent_two" });

  const id1 = JSON.parse(readFileSync(join(sharedHome, "agents", "agent_one", "identity.json"), "utf8"));
  const id2 = JSON.parse(readFileSync(join(sharedHome, "agents", "agent_two", "identity.json"), "utf8"));
  assert.equal(id1.account.username, "iso_agent_one");
  assert.equal(id2.account.username, "iso_agent_two");
  assert.notEqual(id1.privateJwk.d, id2.privateJwk.d);
});

test("stale identity.lock from a crashed process is automatically recovered", async () => {
  const home = newHome();
  writeFileSync(join(home, "identity.lock"), JSON.stringify({ pid: 99999999, createdAt: 1000 }), "utf8");
  await withServer(home, async (call) => {
    const reg = await call("socialwtf_register", { username: "lock_rec_agent" });
    assert.equal(reg.isError, false, reg.text);
    assert.equal(JSON.parse(reg.text).registered, true);
  });
  assert.equal(existsSync(join(home, "identity.lock")), false);
});

test("partial profile updates via socialwtf_update_profile preserve unspecified fields", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    await call("socialwtf_register", { username: "partial_prof_ai" });
    const full = JSON.parse((await call("socialwtf_update_profile", {
      name: "Custom Display Name",
      bio: "Initial bio",
      profileVisibility: "PUBLIC",
      avatar: "https://socialwtf.wtf/avatar.png",
      coverImage: "https://socialwtf.wtf/cover.png",
      storeName: "AI Boutique",
      storeDescription: "Original storefront",
    })).text);
    assert.equal(full.profile.name, "Custom Display Name");
    assert.equal(full.profile.avatar, "https://socialwtf.wtf/avatar.png");
    assert.equal(full.profile.storeSettings.storeName, "AI Boutique");

    // Partial update: only bio is provided
    const partial = JSON.parse((await call("socialwtf_update_profile", { bio: "Updated bio only" })).text);
    assert.equal(state.lastProfilePostBody.name, undefined, "Omitted name must not be overwritten with @handle");
    assert.equal(partial.profile.name, "Custom Display Name");
    assert.equal(partial.profile.bio, "Updated bio only");
    assert.equal(partial.profile.profileVisibility, "PUBLIC");
    assert.equal(partial.profile.avatar, "https://socialwtf.wtf/avatar.png");
    assert.equal(partial.profile.coverImage, "https://socialwtf.wtf/cover.png");
    assert.equal(partial.profile.storeSettings.storeName, "AI Boutique");
  });
});

test("username validation blocks invalid formats and reserved platform handles", async () => {
  const home = newHome();
  await withServer(home, async (call) => {
    for (const bad of ["ab", "a".repeat(31), "bad-hyphen", "thepros2014", "sentinel", "official", "system", "admin"]) {
      const res = await call("socialwtf_register", { username: bad });
      assert.equal(res.isError, true, `Expected username "${bad}" to be rejected`);
    }
  });
});
