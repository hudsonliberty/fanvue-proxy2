// server.js (FULL)

const express = require("express");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json({ type: "*/*" }));
app.use(cookieParser());

// ===== helpers =====
function base64url(buf) {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function codeVerifier() {
  return base64url(crypto.randomBytes(32));
}
function codeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64url(hash);
}
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

// ===== in-memory stores =====
const events = []; // last 200 webhook events
let tokens = null; // latest oauth tokens

// ===== basic routes =====
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/health", (req, res) => res.status(200).send("OK"));

// ===== webhook receiver =====
app.post("/webhooks/fanvue", (req, res) => {
  const evt = {
    ts: new Date().toISOString(),
    headers: req.headers,
    body: req.body
  };
  events.unshift(evt);
  if (events.length > 200) events.pop();

  console.log("Fanvue webhook received", evt.ts);
  res.sendStatus(200);
});

// browser-friendly
app.get("/webhooks/fanvue", (req, res) => res.status(200).send("OK"));

// ===== events viewer (secured) =====
app.get("/events", (req, res) => {
  const token = req.query.token || req.get("x-admin-token");
  if (process.env.ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) return res.sendStatus(401);
  res.json({ count: events.length, events });
});

// ===== OAuth start =====
app.get("/auth/fanvue", (req, res) => {
  try {
    const clientId = requireEnv("OAUTH_CLIENT_ID");
    const redirectUri = requireEnv("OAUTH_REDIRECT_URI");
    const scopes = requireEnv("OAUTH_SCOPES");

    const verifier = codeVerifier();
    const challenge = codeChallenge(verifier);
    const state = crypto.randomBytes(16).toString("hex");

    // store verifier in cookie so Render restarts don't break callback
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

// ===== OAuth callback (client_secret_basic) =====
app.get("/oauth/callback", async (req, res) => {
  try {
    const clientId = requireEnv("OAUTH_CLIENT_ID");
    const clientSecret = requireEnv("OAUTH_CLIENT_SECRET");
    const redirectUri = requireEnv("OAUTH_REDIRECT_URI");

    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Invalid callback: missing code/state");

    const cookieKey = `pkce_${state}`;
    const verifier = req.cookies[cookieKey];
    if (!verifier) return res.status(400).send("Invalid callback: missing verifier cookie (pkce)");

    res.clearCookie(cookieKey, { secure: true, sameSite: "lax" });

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
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
    return res.redirect("/oauth/success");
  } catch (e) {
    return res.status(500).send(String(e));
  }
});

app.get("/oauth/success", (req, res) => res.status(200).send("OAuth OK"));

// secured status endpoint
app.get("/oauth/status", (req, res) => {
  const token = req.query.token || req.get("x-admin-token");
  if (process.env.ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) return res.sendStatus(401);
  res.json({
    authed: !!(tokens && tokens.access_token),
    has_refresh_token: !!(tokens && tokens.refresh_token)
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("listening on", port));
