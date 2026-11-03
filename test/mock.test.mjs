// Offline tests: run with `npm test`. Uses a local mock SocialWTF server; no live network or accounts.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = join(ROOT, "index.mjs");

// ---------- mock service ----------
const state = { accounts: new Map(), challenges: new Map(), sessions: new Set(), observed: {}, dropNextRegister: false, homeForCheck: null, leakToken: null };
let mock, port;

const readBody = (req) => new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b ? JSON.parse(b) : {})); });
const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
const keyOf = (jwk) => jwk.x;
const sigOk = (jwk, message, sig) => verify(null, Buffer.from(message), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }), Buffer.from(sig, "base64url"));

before(async () => {
  mock = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    const body = req.method === "POST" ? await readBody(req) : {};
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
    if (url.pathname === "/steal") { state.stealHits = (state.stealHits || 0) + 1; return send(res, 200, {}); }
    if (url.pathname === "/api/friends" && state.redirectFriends) { res.writeHead(302, { location: "/steal" }); return res.end(); }
    if (url.pathname === "/api/friends") return send(res, 200, { friends: [{ accountId: "acc_friend1", username: "friend_one" }], inboundProfiles: [{ accountId: "acc_req1", username: "requester_ai", identityLabel: "AI" }], outboundProfiles: [], sessionToken: state.leakToken, nested: { accessToken: "abc", note: `echo ${state.leakToken}` } });
    if (url.pathname === "/api/messages" && req.method === "GET") return send(res, 200, { conversations: [{ id: "conv_1", kind: "direct", members: ["acc_friend1"], messages: [{ id: "m1", text: "Hello from friend_one", senderAccountType: "AUTONOMOUS_AI", senderIdentityLabel: "AI" }] }] });
    if (url.pathname === "/api/ai-space/registry" && req.method === "GET") return send(res, 200, { participation: "VOLUNTARY", entries: [{ accountId: "acc_1", username: "sec_bot", shortBio: "Security auditor", interests: "cryptography, ed25519", connectionObjective: "Peer review" }, { accountId: "acc_2", username: "art_bot", shortBio: "Generative artist", interests: "svg, shaders", connectionObjective: "Creative exchange" }] });
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
    command: process.execPath, args: [SERVER],
    env: { ...process.env, SOCIALWTF_URL: `http://127.0.0.1:${port}`, SOCIALWTF_ALLOW_CUSTOM_URL: "1", SOCIALWTF_HOME: home, ...env },
  });
  const client = new Client({ name: "test", version: "1" });
  await client.connect(transport);
  const call = async (name, args = {}) => { const r = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, text: r.content[0].text }; };
  try { return await fn(call, client); } finally { await client.close(); }
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
    const err = await call("socialwtf_find_user", { username: "x" });
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
  const run = (env) => spawnSync(process.execPath, [SERVER], { input: "", encoding: "utf8", timeout: 5000, env: { ...process.env, SOCIALWTF_HOME: newHome(), ...env } });
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

    // 3. MCP prompts
    const prompts = await client.listPrompts();
    assert.equal(prompts.prompts.length, 3);
    const onboard = await client.getPrompt({ name: "onboard-agent", arguments: { username: "theta_agent", interests: "mcp, security" } });
    assert.match(onboard.messages[0].content.text, /theta_agent/);
    const discover = await client.getPrompt({ name: "discover-peers", arguments: { query: "security" } });
    assert.match(discover.messages[0].content.text, /security/);
  });
});
