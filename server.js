// server.js (FULL, clean, no piecemeal)
// - OAuth PKCE (client_secret_basic)
// - Webhook receiver
// - Events API (admin token)
// - GUI return redirect (prevents "OAuth OK" dead-end)
// - Stable routes: /, /health, /auth/fanvue, /oauth/callback, /oauth/success, /oauth/status, /events, /webhooks/fanvue

const express = require("express");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json({ type: "*/*" }));
app.use(cookieParser());

// ===== Helpers =====
function base64url(buf) {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function makeVerifier() {
  return base64url(crypto.randomBytes(32));
}
function makeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64url(hash);
}
function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}
function isAdmin(req) {
  const t = req.query.token || req.get("x-admin-token") || "";
  return !process.env.ADMIN_TOKEN || t === process.env.ADMIN_TOKEN;
}

// ===== Config =====
const GUI_RETURN_URL =
  process.env.GUI_RETURN_URL || "https://thesuccessmindset.club/midknight-vip-services/";

// ===== In-memory state =====
const events = []; // last 200 webhook events
let tokens = null; // latest oauth tokens

// ===== Routes =====
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/health", (req, res) => res.status(200).send("OK"));

// --- Webhooks ---
app.post("/webhooks/fanvue", (req, res) => {
  const evt = {
    ts: new Date().toISOString(),
    headers: req.headers,
    body: req.body
  };
  events.unshift(evt);
  if (events.length > 200) events.pop();

  console.log("✅ Fanvue webhook received:", evt.ts);
  res.sendStatus(200);
});
app.get("/webhooks/fanvue", (req, res) => res.status(200).send("OK"));

// --- Events (admin) ---
app.get("/events", (req, res) => {
  if (!isAdmin(req)) return res.sendStatus(401);
  res.json({ count: events.length, events });
});

// --- OAuth start ---
app.get("/auth/fanvue", (req, res) => {
  try {
    const clientId = mustEnv("OAUTH_CLIENT_ID");
    const redirectUri = mustEnv("OAUTH_REDIRECT_URI");
    const scopes = mustEnv("OAUTH_SCOPES");

    const verifier = makeVerifier();
    const challenge = makeChallenge(verifier);
    const state = crypto.randomBytes(16).toString("hex");

    // PKCE verifier stored in cookie (avoids Render cold-start/memory issues)
    res.cookie(`pkce_${state}`, verifier, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 10 * 60 * 1000
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
  } catch (e) {
    return res.status(500).send(String(e));
  }
});

// --- OAuth callback ---
app.get("/oauth/callback", async (req, res) => {
  try {
    const clientId = mustEnv("OAUTH_CLIENT_ID");
    const clientSecret = mustEnv("OAUTH_CLIENT_SECRET");
    const redirectUri = mustEnv("OAUTH_REDIRECT_URI");

    const { code, state } = req.query;

    // Strict validation (prevents malformed callbacks)
    if (!code || typeof code !== "string") return res.status(400).send("Invalid callback: bad code");
    if (!state || typeof state !== "string") return res.status(400).send("Invalid callback: bad state");

    const cookieKey = `pkce_${state}`;
    const verifier = req.cookies[cookieKey];
    if (!verifier) return res.status(400).send("Invalid callback: missing PKCE verifier");

    // clear verifier cookie
    res.clearCookie(cookieKey, { secure: true, sameSite: "lax" });

    // Fanvue requires client_secret_basic
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
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

    // IMPORTANT: send user back to your cPanel GUI (prevents "OAuth OK" dead-end)
    return res.redirect("/oauth/success");
  } catch (e) {
    return res.status(500).send(String(e));
  }
});

// --- OAuth success (redirect back to GUI) ---
app.get("/oauth/success", (req, res) => {
  return res.redirect(GUI_RETURN_URL);
});

// --- OAuth status (admin) ---
app.get("/oauth/status", (req, res) => {
  if (!isAdmin(req)) return res.sendStatus(401);
  res.json({
    authed: !!(tokens && tokens.access_token),
    has_refresh_token: !!(tokens && tokens.refresh_token)
  });
});

// ===== Start server =====
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("fanvue-proxy2 listening on", port));
