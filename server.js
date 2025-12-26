const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ type: "*/*" }));

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

const pkce = new Map(); // state -> verifier
let tokens = null;      // latest token response

app.get("/health", (req, res) => res.status(200).send("OK"));

app.get("/auth/fanvue", (req, res) => {
  const verifier = codeVerifier();
  const challenge = codeChallenge(verifier);
  const state = crypto.randomBytes(16).toString("hex");

  pkce.set(state, verifier);

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("client_id", process.env.OAUTH_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", process.env.OAUTH_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", process.env.OAUTH_SCOPES);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const verifier = pkce.get(state);

    if (!code || !state || !verifier) return res.status(400).send("Invalid callback");

    pkce.delete(state);

    // IMPORTANT: Fanvue requires client_secret_basic
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: process.env.OAUTH_REDIRECT_URI,
      code_verifier: verifier
    });

    const basic = Buffer.from(
      `${process.env.OAUTH_CLIENT_ID}:${process.env.OAUTH_CLIENT_SECRET}`
    ).toString("base64");

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
    return res.status(200).send("OAuth OK");
  } catch (e) {
    return res.status(500).send(String(e));
  }
});

app.get("/oauth/status", (req, res) => {
  const token = req.query.token || req.get("x-admin-token");
  if (process.env.ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) return res.sendStatus(401);
  res.json({ authed: !!(tokens && tokens.access_token) });
});

// Webhook (POST-only)
app.post("/webhooks/fanvue", (req, res) => {
  console.log("Fanvue webhook received", req.body);
  res.sendStatus(200);
});

// Optional: allow browser GET without confusion
app.get("/webhooks/fanvue", (req, res) => res.status(200).send("OK"));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("listening on", port));
