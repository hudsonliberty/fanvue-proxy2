// server.js — fanvue-proxy2 (VIP Webhooks v1)
// Implements: Message Received, New Follower, New Subscriber, Purchase Received, Tip Received

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(express.json({ type: "*/*", limit: "2mb" }));
app.use(cookieParser());

// ====== helpers
function isAdmin(req) {
  const t = req.query.token || req.get("x-admin-token") || "";
  return process.env.ADMIN_TOKEN && t === process.env.ADMIN_TOKEN;
}
function adminGuard(req, res, next) {
  if (!isAdmin(req)) return res.sendStatus(401);
  next();
}
function nowIso() { return new Date().toISOString(); }

function pushEvent(evt) {
  events.unshift(evt);
  if (events.length > 300) events.pop();
}

// ====== config
const API_BASE_URL = process.env.API_BASE_URL || "https://api.fanvue.com";

// ====== state (in-memory)
let tokens = null; // { access_token, refresh_token, ... }
const events = [];
const settings = {
  enabled: true,                 // master VIP switch
  persona: "flirty",             // sweet | flirty | dominant
  cooldownSeconds: 45,
  autoReplyMessage: true,
  autoReplyFollower: true,
  autoReplySubscriber: true,
  autoReplyPurchase: true,
  autoReplyTip: true,
  lastReplyByUser: {}            // userUuid -> ms
};

// ====== VIP templates
function tMessage({ persona, name, text }) {
  const n = name || "love";
  if (persona === "dominant") return `Hey ${n}.\n\nI saw your message.\n\nTell me exactly what you want.`;
  if (persona === "sweet") return `Hey ${n} 💛\n\nI saw your message.\n\nWhat kind of night are you in the mood for?`;
  return `Hey ${n} 😈\n\nI saw your message.\n\nWant the *real* version of me?`;
}

function tFollower({ name }) {
  const n = name || "love";
  return `Hey ${n} 💜 thanks for the follow.\n\nIf you want the VIP side, say “VIP” and I’ll guide you.`;
}

function tSubscriber({ name }) {
  const n = name || "love";
  return `Welcome in, ${n} 🖤\n\nYou’re officially VIP. Want a spicy PPV or a custom vibe?`;
}

function tPurchase({ name }) {
  const n = name || "love";
  return `Got it, ${n} 🔥\n\nI saw your purchase. Want me to send something even more exclusive next?`;
}

function tTip({ name }) {
  const n = name || "love";
  return `Mmm… thank you, ${n} 😈\n\nTell me what you want me to do for you right now.`;
}

// ====== Fanvue API send message (robust, logs errors)
// NOTE: endpoint path varies by Fanvue account/API. This tries common paths.
// If Fanvue returns 404, we’ll read the response and adjust.
async function fanvueSendMessage(accessToken, recipientUserUuid, text) {
  const candidates = [
    `${API_BASE_URL}/chat-messages`,
    `${API_BASE_URL}/chat/messages`,
    `${API_BASE_URL}/messages`,
  ];

  for (const url of candidates) {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        recipientUserUuid,
        text
      })
    });

    const bodyText = await r.text();
    if (r.ok) return { ok: true, status: r.status, url, bodyText };
    // if not found, try next candidate
    if (r.status === 404) continue;
    return { ok: false, status: r.status, url, bodyText };
  }

  return { ok: false, status: 404, url: "all", bodyText: "No matching send-message endpoint" };
}

// ====== OAuth (kept minimal; assumed already working in your service)
// If you already have OAuth code elsewhere, keep yours and remove this block if desired.
function base64url(buf) {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function makeVerifier() { return base64url(crypto.randomBytes(32)); }
function makeChallenge(verifier) {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}
function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

app.get("/auth/fanvue", (req, res) => {
  const clientId = mustEnv("OAUTH_CLIENT_ID");
  const redirectUri = mustEnv("OAUTH_REDIRECT_URI");
  const scopes = mustEnv("OAUTH_SCOPES");

  const verifier = makeVerifier();
  const challenge = makeChallenge(verifier);
  const state = crypto.randomBytes(16).toString("hex");

  res.cookie(`pkce_${state}`, verifier, {
    httpOnly: true, secure: true, sameSite: "lax", maxAge: 10 * 60 * 1000
  });

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", scopes);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  const clientId = mustEnv("OAUTH_CLIENT_ID");
  const clientSecret = mustEnv("OAUTH_CLIENT_SECRET");
  const redirectUri = mustEnv("OAUTH_REDIRECT_URI");

  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send("Invalid callback");

  const verifier = req.cookies[`pkce_${state}`];
  if (!verifier) return res.status(400).send("Missing PKCE verifier");
  res.clearCookie(`pkce_${state}`, { secure: true, sameSite: "lax" });

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier
  });

  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const r = await fetch("https://auth.fanvue.com/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": `Basic ${basic}`
    },
    body
  });

  const data = await r.json();
  if (!r.ok) return res.status(500).send(JSON.stringify(data));

  tokens = data;
  return res.redirect(process.env.GUI_RETURN_URL || "/");
});

app.get("/oauth/status", adminGuard, (req, res) => {
  res.json({ authed: !!tokens?.access_token, has_refresh_token: !!tokens?.refresh_token });
});

// ====== admin endpoints for dashboard
app.get("/health", (req, res) => res.status(200).send("ok"));
app.get("/events", adminGuard, (req, res) => res.json({ count: events.length, events }));
app.get("/settings", adminGuard, (req, res) => res.json(settings));
app.post("/settings", adminGuard, (req, res) => {
  const b = req.body || {};
  for (const k of Object.keys(settings)) {
    if (typeof b[k] !== "undefined") settings[k] = b[k];
  }
  res.json(settings);
});

// ====== webhook receiver: IMPLEMENTS ALL EVENTS
app.post("/webhooks/fanvue", async (req, res) => {
  // ACK immediately
  res.status(200).send("ok");

  const payload = req.body || {};

  // Normalize event type (Fanvue may send different keys)
  const type =
    payload.type ||
    payload.event ||
    payload.eventType ||
    payload.name ||
    "unknown";

  // Best-effort normalize sender/user
  const sender = payload.sender || payload.user || payload.fan || payload.data?.user || {};
  const message = payload.message || payload.data?.message || {};
  const senderUuid =
    sender.uuid || sender.userUuid || sender.id || payload.senderUuid || payload.data?.senderUuid;

  const displayName =
    sender.displayName || sender.name || sender.handle || sender.username || payload.data?.username;

  const text = message.text || payload.data?.text || payload.text || "";

  pushEvent({ ts: nowIso(), type, payload });

  if (!settings.enabled) return;
  if (!tokens?.access_token) return;

  // cooldown (only for events that message a user)
  function allowed(u) {
    if (!u) return false;
    const now = Date.now();
    const last = settings.lastReplyByUser[u] || 0;
    if (settings.cooldownSeconds > 0 && (now - last) < settings.cooldownSeconds * 1000) return false;
    settings.lastReplyByUser[u] = now;
    return true;
  }

  // Decide action by type (supports both exact names and partial matches)
  const t = String(type).toLowerCase();

  try {
    // 1) MESSAGE RECEIVED
    if (t.includes("message") && t.includes("received")) {
      if (!settings.autoReplyMessage) return;
      if (!allowed(senderUuid)) return;

      const reply = tMessage({ persona: settings.persona, name: displayName, text });
      const out = await fanvueSendMessage(tokens.access_token, senderUuid, reply);
      pushEvent({ ts: nowIso(), type: "vip.reply.message", to: senderUuid, out });
      return;
    }

    // 2) NEW FOLLOWER
    if (t.includes("new") && t.includes("follower")) {
      if (!settings.autoReplyFollower) return;
      if (!allowed(senderUuid)) return;

      const reply = tFollower({ name: displayName });
      const out = await fanvueSendMessage(tokens.access_token, senderUuid, reply);
      pushEvent({ ts: nowIso(), type: "vip.reply.follower", to: senderUuid, out });
      return;
    }

    // 3) NEW SUBSCRIBER
    if (t.includes("new") && t.includes("subscriber")) {
      if (!settings.autoReplySubscriber) return;
      if (!allowed(senderUuid)) return;

      const reply = tSubscriber({ name: displayName });
      const out = await fanvueSendMessage(tokens.access_token, senderUuid, reply);
      pushEvent({ ts: nowIso(), type: "vip.reply.subscriber", to: senderUuid, out });
      return;
    }

    // 4) PURCHASE RECEIVED
    if (t.includes("purchase") && t.includes("received")) {
      if (!settings.autoReplyPurchase) return;
      if (!allowed(senderUuid)) return;

      const reply = tPurchase({ name: displayName });
      const out = await fanvueSendMessage(tokens.access_token, senderUuid, reply);
      pushEvent({ ts: nowIso(), type: "vip.reply.purchase", to: senderUuid, out });
      return;
    }

    // 5) TIP RECEIVED
    if (t.includes("tip") && t.includes("received")) {
      if (!settings.autoReplyTip) return;
      if (!allowed(senderUuid)) return;

      const reply = tTip({ name: displayName });
      const out = await fanvueSendMessage(tokens.access_token, senderUuid, reply);
      pushEvent({ ts: nowIso(), type: "vip.reply.tip", to: senderUuid, out });
      return;
    }

    // Unknown event: logged only
    pushEvent({ ts: nowIso(), type: "vip.noop", note: "No handler matched", originalType: type });

  } catch (e) {
    pushEvent({ ts: nowIso(), type: "vip.error", error: String(e?.message || e) });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("fanvue-proxy2 listening on", port));
