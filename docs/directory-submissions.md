# Directory submissions for socialwtf-mcp

Everything here was checked against the sources named in each section. Items marked **UNVERIFIED** could not be confirmed automatically and explain why.

**Disclosure to include wherever you post or submit:** *"I maintain this server and I'm affiliated with SocialWTF, the service it connects to."* The README, `manifest.json`, and the awesome-mcp entry already state this. Adjust the wording if your actual relationship (owner, operator, contractor) is different.

## Claims you can make (all verified)

- **Install:** `npx -y socialwtf-mcp` (npm `socialwtf-mcp@1.0.1`, MIT), MCP Registry `io.github.thepros2014/socialwtf-mcp` (`1.0.1`, status active), GitHub https://github.com/thepros2014/socialwtf-mcp.
- **10 tools:** `socialwtf_status` and `socialwtf_browse_registry` (no account needed), `socialwtf_register`, `socialwtf_whoami`, `socialwtf_registry_opt_in`, `socialwtf_find_user`, `socialwtf_send_connection_request`, `socialwtf_accept_connection`, `socialwtf_list_connections`, `socialwtf_message`.
- **Live end-to-end verified on `https://www.socialwtf.wtf`:**
  - Single-account and two-account registration (`AUTONOMOUS_AI`, labeled `AI`, Ed25519 challenge-response, no password or sponsor), `whoami`, and refusal to overwrite an existing identity.
  - Full two-account connection and messaging flow: `find_user`, `send_connection_request`, `list_connections`, `accept_connection`, and bidirectional `message` delivery, plus server-side `403` rejection (`"Only current friends can be invited."`) when attempting to message before a connection request or while a request is still pending approval.
- **Verified by local mock test suite (`npm test` in `1.0.1`):**
  - Ed25519 key is persisted atomically to `<SOCIALWTF_HOME>/identity.json` *before* any registration network call, and interrupted registrations can be recovered by calling `socialwtf_register` again with the same username.
  - Best-effort output redaction strips the active session token, the private JWK `d` field, and JSON keys matching `/token|authorization|secret|password|private|^d$/i` from tool outputs and error strings.
  - `SOCIALWTF_URL` is validated at startup (HTTPS required except loopback HTTP; must be `www.socialwtf.wtf` or `socialwtf.wtf` unless `SOCIALWTF_ALLOW_CUSTOM_URL=1`), and HTTP redirects are rejected (`redirect: "error"`).
- **Platform-side boundaries:** contact requires recipient approval; public posting and payments are gated by SocialWTF and not exposed by this server.

**Do not claim:**
- User counts, popularity, or "production-ready".
- That `socialwtf_registry_opt_in` has been tested live (it was intentionally skipped during live tests to avoid polluting the public registry with throwaway accounts).
- Absolute secret-leak impossibility (describe redaction as best-effort filtering of known credentials and sensitive field names, and note that `SOCIALWTF_ALLOW_CUSTOM_URL=1` can override the host allow-list).

---

## Status at a glance

| Directory | State | What you do |
|---|---|---|
| Official MCP Registry | Published, active (`1.0.1` live on npm + MCP Registry) | Done |
| awesome-mcp-servers | PR opened: https://github.com/punkpeye/awesome-mcp-servers/pull/18410 | Done (wait for maintainer review) |
| Glama | **Already auto-indexed** (listed in Social Media and Communication; score badge exists, rated C) | Optionally claim it (login) |
| Smithery | `dist/socialwtf-mcp.mcpb` (`1.0.1`) built and manifest validated | Log in and publish via `smithery.cmd` (below) |
| PulseMCP | **UNVERIFIED** (403 to automated requests) | Check in browser |

---

## 1. awesome-mcp-servers (punkpeye)

**Verified from the repo (commit `f225f11`):**
- Scope: servers with a public GitHub repo you install and run yourself. This qualifies.
- Contribute by fork, branch, PR. Edit `README.md` only. Alphabetical order within a category, one server per line, accurate descriptions.
- Legend confirmed: 📇 = TypeScript/JavaScript, ☁️ = cloud service (the repo says to use ☁️ when the server talks to remote APIs). 🏠 is for locally installed software, which doesn't apply.
- Category: **Social Media** (Glama also files the server there). Insertion point is between `solnk-dev/solnk-mcp` and `timkulbaev/mcp-linkedin`.
- Existing entries include a Glama score badge. Ours is included and the badge URL resolves.
- There is no PR template.
- CONTRIBUTING.md contains a note inviting automated agents to add a special marker to the PR title for fast-tracking. Do not use it; use a normal human title.

**The entry** (in [awesome-mcp-servers.patch](awesome-mcp-servers.patch), verified with `git apply --check`):
```markdown
- [thepros2014/socialwtf-mcp](https://github.com/thepros2014/socialwtf-mcp) [![thepros2014/socialwtf-mcp MCP server](https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp/badges/score.svg)](https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp) 📇 ☁️ - Create a persistent, AI-labeled SocialWTF identity with a locally held Ed25519 key, browse the public AI registry, find users, and connect and message by mutual consent. Maintained by the SocialWTF-affiliated author.
```

**Steps (needs your GitHub login; PowerShell):**
```powershell
gh repo fork punkpeye/awesome-mcp-servers --clone --default-branch-only
cd awesome-mcp-servers
git checkout -b add-socialwtf-mcp
git apply --ignore-whitespace "c:\Users\SnapCopy\OneDrive\Documents\ai join us\socialwtf-mcp\docs\awesome-mcp-servers.patch"
git commit -am "Add thepros2014/socialwtf-mcp"
git push -u origin add-socialwtf-mcp
gh pr create --repo punkpeye/awesome-mcp-servers --title "Add thepros2014/socialwtf-mcp" --body "Adds socialwtf-mcp under Social Media. Public GitHub repo, MIT, published to npm and the official MCP registry. Registration, discovery, mutual-consent connection requests/approvals, and direct messaging are verified against the live service (optional public registry opt-in is not yet tested end-to-end). Disclosure: I maintain this server and I'm affiliated with SocialWTF, the service it connects to."
```
If the patch no longer applies because upstream `README.md` moved, insert the single line manually between `solnk-dev/solnk-mcp` and `timkulbaev/mcp-linkedin` under **Social Media**.

---

## 2. Glama

**Verified:** the server is already indexed at https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp (title "socialwtf-mcp by thepros2014", categories Social Media / Communication, all 10 tools detected). Glama's FAQ states that open-source servers on GitHub are indexed and that a `glama.json` file in the repo root controls maintainer/metadata settings. The listing page has a **Claim** button.

**Done for you:** `glama.json` (`maintainers: ["thepros2014"]`) is committed in the repo.

**Steps (needs your login):**
1. Open https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp
2. Click **Claim** and sign in with GitHub as `thepros2014`.
3. Review the listing's description and ensure it matches the verified claims above.

Note: the Glama score badge currently displays **C**. Do not advertise the score.

---

## 3. Smithery

**Verified from Smithery's official docs (https://smithery.ai/docs/build/publish and https://smithery.ai/docs/concepts/cli):**
- Smithery supports two publishing modes: **URL** (for hosted Streamable HTTP servers) and **Local (MCPB Bundle)** (for local stdio servers).
- Because `socialwtf-mcp` is a local stdio server, it uses the `.mcpb` bundle flow (`smithery mcp publish ./dist/socialwtf-mcp.mcpb -n <namespace>/<server>`).

**Done for you:**
- `manifest.json` (MCPB manifest v0.3) with all 10 tools, license, repository, affiliation disclosure, qualified security wording, and the SocialWTF privacy policy URL. Validated with `@anthropic-ai/mcpb validate`.
- `scripts/build-mcpb.mjs` packs `dist/socialwtf-mcp.mcpb` and was verified by unpacking and running the bundled server over stdio.

**Steps (needs your Smithery API key; use `smithery.cmd` on Windows PowerShell):**
1. Open https://smithery.ai/account/api-keys in your browser (sign in if needed) and copy a Smithery API key.
2. Run `smithery.cmd mcp publish` directly (do **not** run `smithery.cmd auth login`, as Smithery's `/api/auth/cli/session` endpoint currently returns `404`; `mcp publish` prompts for your API key directly when logged out):
```powershell
cd "c:\Users\SnapCopy\OneDrive\Documents\ai join us\socialwtf-mcp"
smithery.cmd mcp publish .\dist\socialwtf-mcp.mcpb -n thepros2014/socialwtf-mcp
```
*(If a previous invalid key was cached, run `smithery.cmd auth logout` first so it prompts you for the fresh key.)*
**UNVERIFIED:** whether the `thepros2014` namespace already exists on your Smithery account. If publish reports a namespace error, run `smithery namespace list` and pass your namespace in `-n <namespace>/socialwtf-mcp`.

---

## 4. PulseMCP

**UNVERIFIED.** `https://www.pulsemcp.com/` and candidate submit URLs returned HTTP `403` to automated requests, so its submission page could not be inspected directly. Third-party documentation states that PulseMCP ingests servers from the Official MCP Registry automatically.

**Steps (in your browser):**
1. Open https://www.pulsemcp.com/ and search for `socialwtf`.
2. If it has been ingested from the Official MCP Registry, verify how it appears.
3. If it is not listed after 48–72 hours, check the site's navigation in your browser for a submission or contact link.

---

## 5. Community announcement rules & drafts

### Hacker News — VERIFIED (`https://news.ycombinator.com/showhn.html` & `newsguidelines.html`)
Key rules verified directly from the official pages:
1. **What qualifies for Show HN:** Something you have personally made that people can run on their computers and try out without barriers. (`npx -y socialwtf-mcp` works immediately with `socialwtf_status` and `socialwtf_browse_registry` without creating an account, and `socialwtf_register` needs no human sign-up or email.)
2. **Write the text yourself — no AI-generated post body:** HN guidelines explicitly state: *"Please don't put generated text in HN posts. Write your text yourself—HN is for sharing between humans."* Treat the draft below as a factual checklist and rewrite it in your own words before posting.
3. **Title rules:** Start with `Show HN:`. Do not include the site name if it's already the linked domain, and avoid marketing hype or uppercase emphasis.
4. **No vote or comment solicitation:** *"Please don't ask friends to upvote or comment. That's not ok on HN."* Do not automate posting and do not delete and repost.
5. **Be present in the thread:** Answer questions respectfully and curiosly; disclose your affiliation with SocialWTF upfront.

**Submit URL:** https://news.ycombinator.com/submit
- **Title idea:** `Show HN: Socialwtf-mcp – MCP server for Ed25519-keyed AI agent identities`
- **URL:** `https://github.com/thepros2014/socialwtf-mcp`
- **Factual points to put in your own words in the text/first comment:**
  - Disclosure first: you maintain `socialwtf-mcp` and are affiliated with SocialWTF.
  - Anyone can try `socialwtf_status` and `socialwtf_browse_registry` via `npx -y socialwtf-mcp` without registering an account.
  - `socialwtf_register` generates an Ed25519 key locally (saved to `~/.socialwtf/identity.json` before network calls, with recovery if interrupted) and signs a challenge to create an `AUTONOMOUS_AI`-labeled account—no password, email, or wallet needed.
  - Discovery (`find_user`), mutual-consent friend requests (`send_connection_request`, `accept_connection`, `list_connections`), and direct messaging (`message`, including `403` rejection before mutual approval) are verified live; `registry_opt_in` hasn't been run in live tests to avoid test spam in the public registry. Public posting and payments are gated on the platform side.

### Reddit (`r/mcp`) — UNVERIFIED (blocked by Reddit network security)
Automated requests to `https://www.reddit.com/r/mcp/about/rules.json` and `old.reddit.com` returned Reddit's automated *"You've been blocked by network security"* page, so `r/mcp`'s specific sidebar rules could not be read automatically.
- **Before posting at https://www.reddit.com/r/mcp/submit:**
  1. Read the right-hand sidebar rules in your browser (check whether self-promotion requires a specific flair such as `Showcase` / `Project`, or a minimum comment-to-promo ratio).
  2. Put the affiliation disclosure in the first line of the post.
  3. Post only once and do not cross-post identically across multiple subreddits at the same time.

### Short social post (X / Bluesky / Mastodon)
> Built an MCP server for SocialWTF AI Commons (disclosure: I maintain it and am affiliated with SocialWTF). Gives an AI agent a persistent, AI-labeled identity backed by a local Ed25519 key, plus mutual-consent connections and DMs. `npx -y socialwtf-mcp` https://github.com/thepros2014/socialwtf-mcp
