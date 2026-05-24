require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 10000;

app.set("trust proxy", true);

// --- ENV ---
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();

const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();

// --- In-memory stores ---
const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const MAX_EVENTS = 100;

// --- Raw-body capture ---
function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

// --- Middleware ---
app.use(
  express.json({
    limit: "2mb",
    verify: rawBodySaver,
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers ---
function baseUrl(req) {
  return `https://${req.get("host")}`;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next();

  const got = (req.get("x-admin-token") || "").trim();
  if (got && got === ADMIN_TOKEN) return next();

  return res.status(401).json({ error: "Unauthorized" });
}

function getSession(req) {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function setSessionCookie(res, sid) {
  res.cookie(COOKIE_NAME, sid, {
    signed: true,
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

// ... (keep your verifyFanvueSignature, normalizeWebhook, addEvent unchanged)

function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  const codeVerifier = crypto
    .randomBytes(32)
    .toString("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  oauthStates.set(state, {
    nonce,
    codeVerifier,
    ts: Date.now(),
  });

  // Cleanup old states
  if (oauthStates.size > 100) {
    for (const [key, val] of oauthStates) {
      if (Date.now() - val.ts > 10 * 60 * 1000) oauthStates.delete(key);
    }
  }

  return { state, nonce, codeVerifier, codeChallenge };
}

// =========================
// HELPERS FOR TOKEN EXCHANGE
// =========================

async function exchangeCodeForToken(clientId, clientSecret, code, redirectUri, codeVerifier) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  const tokenResp = await axios.post(
    "https://auth.fanvue.com/oauth2/token",
    params.toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 20000,
    }
  );

  return tokenResp.data;
}

// =========================
// ROUTES
// =========================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/health", (req, res) => res.status(200).send("ok"));

// =========================
// ORIGINAL MVP OAUTH
// =========================

app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(503).send("Missing CLIENT_ID / CLIENT_SECRET");
  }

  const pkce = createPkceState();
  const redirectUri = `${baseUrl(req)}/oauth/callback`;

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access read:self read:fan read:insights");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error("Fanvue OAuth error:", error, error_description);
    return res.status(400).send(`Authorization error: ${error} ${error_description || ""}`);
  }

  if (!code || !state) {
    return res.status(400).send("Missing code or state");
  }

  const st = oauthStates.get(state);
  if (!st) {
    return res.status(400).send("Invalid/expired state. Please try again.");
  }
  oauthStates.delete(state);

  try {
    const redirectUri = `${baseUrl(req)}/oauth/callback`;

    const tokenData = await exchangeCodeForToken(
      CLIENT_ID,
      CLIENT_SECRET,
      code,
      redirectUri,
      st.codeVerifier
    );

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error("No access_token received");

    // Get profile
    const profileResp = await axios.get("https://api.fanvue.com/users/me", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": "2025-06-26",
      },
      timeout: 15000,
    });

    const creator = profileResp.data || {};

    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, { accessToken, creator, ts: Date.now() });

    setSessionCookie(res, sid);

    console.log("✅ MVP OAuth successful for", creator.handle || creator.displayName);
    return res.redirect("/");
  } catch (err) {
    console.error("OAuth callback failed:", {
      status: err?.response?.status,
      data: err?.response?.data,
      message: err.message,
    });
    return res.status(500).send(`Authentication failed: ${err.message}`);
  }
});

// =========================
// DANIAPP OAUTH
// =========================

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth environment variables");
  }

  const pkce = createPkceState();
  const redirectUri = DANI_REDIRECT_URI;

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access write:post write:media");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error("DaniApp OAuth error:", error, error_description);
    return res.status(400).send(`Fanvue denied: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state");

  oauthStates.delete(state);

  try {
    const tokenData = await exchangeCodeForToken(
      DANI_CLIENT_ID,
      DANI_CLIENT_SECRET,
      code,
      DANI_REDIRECT_URI,
      st.codeVerifier
    );

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error("No access_token received");

    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, {
      accessToken,
      creator: { app: "On My Time", connected: true },
      ts: Date.now(),
    });

    setSessionCookie(res, sid);

    console.log("✅ DaniApp OAuth successful");
    return res.redirect("https://thesuccessmindset.club/daniapp/index.html?connected=1");
  } catch (err) {
    console.error("DaniApp OAuth failed:", {
      status: err?.response?.status,
      data: err?.response?.data,
      message: err.message,
    });
    return res.status(500).send("DaniApp connection failed. Check server logs.");
  }
});

// ... rest of your routes (api/me, logout, webhooks, etc.) remain the same

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("=".repeat(60));
  console.log(`Dashboard: https://fanvue-proxy2.onrender.com/`);
  // ... other logs
});
