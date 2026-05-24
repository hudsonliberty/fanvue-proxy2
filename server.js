require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const { parse } = require("csv-parse/sync");
const XLSX = require("xlsx");

const app = express();
const PORT = process.env.PORT || 10000;

const upload = multer({ storage: multer.memoryStorage() });

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
const FANVUE_API_VERSION = "2025-06-26";

// --- Stores ---
const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const MAX_EVENTS = 100;

// --- Middleware ---
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers ---
function baseUrl(req) {
  return `https://${req.get("host")}`;
}

function getSession(req) {
  const sid = req.signedCookies?.[COOKIE_NAME];
  return sid ? sessions.get(sid) : null;
}

function setSessionCookie(res, sid) {
  res.cookie(COOKIE_NAME, sid, {
    signed: true,
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  const codeChallenge = crypto.createHash("sha256")
    .update(codeVerifier).digest("base64url")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  oauthStates.set(state, { codeVerifier, ts: Date.now() });
  return { state, codeVerifier, codeChallenge };
}

// === IMPROVED TOKEN EXCHANGE (Official Fanvue way) ===
async function exchangeToken(clientId, clientSecret, code, redirectUri, codeVerifier) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  console.log("🔄 Token exchange - redirect_uri:", redirectUri);

  const resp = await axios.post(
    "https://auth.fanvue.com/oauth2/token",
    params.toString(),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 30000,
    }
  );
  return resp.data;
}

// Keep all your other helper functions (extractCreatorProfile, uploadMediaAndCreatePost, etc.)
// ... paste them here from your previous version (they are good)

// =========================
// DANIAPP OAUTH (Fixed)
// =========================
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth credentials");
  }

  const pkce = createPkceState();
  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid offline_access write:post write:media read:self");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  console.log("🚀 DaniApp OAuth Start URL:", authUrl.toString());
  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  console.log("📥 Callback hit:", { hasCode: !!code, state, error, error_description });

  if (error) {
    console.error("Fanvue Error:", error, error_description);
    return res.status(400).send(`Fanvue denied: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const stored = oauthStates.get(state);
  if (!stored) {
    console.error("State not found:", state);
    return res.status(400).send("Invalid/expired state. Try again.");
  }

  oauthStates.delete(state);

  try {
    const tokenData = await exchangeToken(
      DANI_CLIENT_ID,
      DANI_CLIENT_SECRET,
      code,
      DANI_REDIRECT_URI,
      stored.codeVerifier
    );

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error("No access_token returned");

    console.log("✅ Token exchange SUCCESS");

    // Create session
    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, {
      accessToken,
      creator: { app: "On My Time", connected: true },
      ts: Date.now()
    });

    setSessionCookie(res, sid);

    return res.redirect("https://thesuccessmindset.club/daniapp/index.html?connected=1");
  } catch (err) {
    console.error("🔥 TOKEN EXCHANGE FAILED:", {
      status: err?.response?.status,
      data: err?.response?.data,
      message: err.message
    });

    return res.status(500).send(`
      <h2>Connection Failed</h2>
      <p>Check Render Logs for exact error.</p>
    `);
  }
});

// === Your other routes (MVP OAuth, /daniapp/api/post, bulk, etc.) go here ===
// You can keep them exactly as you had them.

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY - DaniApp OAuth Fixed");
  console.log("=".repeat(60));
});
