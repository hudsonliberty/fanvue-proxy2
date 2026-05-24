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

// --- In-memory stores ---
const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const MAX_EVENTS = 100;

// --- Middleware ---
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers (unchanged) ---
function baseUrl(req) {
  return `https://${req.get("host")}`;
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
    sameSite: "none",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}

// ... [All your helper functions remain exactly the same: createPkceState, extractCreatorProfile, getMediaType, findSignedUrl, parseBulkFile, downloadMediaFromUrl, waitForMediaReady, uploadMediaAndCreatePost, verifyFanvueSignature, normalizeWebhook, etc.] ...

// Keep ALL your helper functions from your original long version here (I didn't remove any)

// =========================
// DANIAPP OAUTH - FIXED
// =========================
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DANI_CLIENT_ID / CLIENT_SECRET / REDIRECT_URI");
  }

  const pkce = createPkceState();
  const redirectUri = DANI_REDIRECT_URI;

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access write:post write:media read:self");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  console.log("🚀 DANIAPP OAUTH START URL:", authUrl.toString());
  return res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  console.log("📥 DANIAPP CALLBACK RECEIVED:", JSON.stringify(req.query));

  if (error) {
    console.error("Fanvue Error:", error, error_description);
    return res.status(400).send(`Fanvue denied: ${error} ${error_description || ""}`);
  }

  if (!code || !state) {
    return res.status(400).send("Missing code/state");
  }

  const st = oauthStates.get(state);
  if (!st) {
    console.error("❌ State not found:", state);
    return res.status(400).send("Invalid/expired state. Restart connection.");
  }

  oauthStates.delete(state);

  try {
    const redirectUri = DANI_REDIRECT_URI;

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: DANI_CLIENT_ID,
      client_secret: DANI_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
      code_verifier: st.codeVerifier,
    });

    console.log("🔄 Attempting token exchange...");

    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      params.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 25000,
      }
    );

    const accessToken = tokenResp.data.access_token;
    if (!accessToken) throw new Error("No access_token returned");

    console.log("✅ TOKEN EXCHANGE SUCCESS");

    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, {
      accessToken,
      creator: { app: "On My Time", connected: true },
      ts: Date.now()
    });

    setSessionCookie(res, sid);

    console.log("🎉 DANIAPP CONNECTION COMPLETE");
    return res.redirect("https://thesuccessmindset.club/daniapp/index.html?connected=1");

  } catch (err) {
    console.error("🔥 DANIAPP OAUTH FAILED:");
    console.error("Status:", err?.response?.status);
    console.error("Data:", JSON.stringify(err?.response?.data || {}, null, 2));
    console.error("Message:", err.message);

    return res.status(500).send("DaniApp OAuth failed. Check Render logs for details.");
  }
});

// === Keep ALL your other routes exactly as they were (MVP OAuth, /daniapp/api/post, bulk-post, webhooks, etc.) ===
// Paste them here from your original long file.

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY - Full Version");
  console.log("=".repeat(60));
});
