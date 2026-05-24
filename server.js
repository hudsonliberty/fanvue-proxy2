require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const upload = multer({ storage: multer.memoryStorage() });

app.set("trust proxy", true);

// --- ENV ---
const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();

// --- Middleware ---
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

// --- Stores ---
const oauthStates = new Map();
const sessions = new Map();

// --- Helpers ---
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

async function exchangeToken(clientId, clientSecret, code, redirectUri, codeVerifier) {
  console.log("🔄 [TOKEN EXCHANGE] Starting with redirect_uri:", redirectUri);
  console.log("🔄 Client ID length:", clientId?.length);

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  try {
    const resp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      params.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 30000,
      }
    );
    console.log("✅ Token exchange SUCCESS");
    return resp.data;
  } catch (err) {
    console.error("❌ TOKEN EXCHANGE FAILED");
    console.error("Status:", err?.response?.status);
    console.error("Response Data:", JSON.stringify(err?.response?.data, null, 2));
    console.error("Message:", err.message);
    throw err;
  }
}

// =========================
// DANIAPP OAUTH
// =========================
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth environment variables on Render");
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

  console.log("🚀 START URL:", authUrl.toString());
  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  console.log("📥 CALLBACK RECEIVED:", { code: !!code, state, error, error_description, fullQuery: req.query });

  if (error) {
    return res.status(400).send(`Fanvue Error: ${error} - ${error_description || ''}`);
  }

  if (!code || !state) {
    return res.status(400).send("Missing code or state");
  }

  const stored = oauthStates.get(state);
  if (!stored) {
    return res.status(400).send("Invalid or expired state. Please try again.");
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
    if (!accessToken) throw new Error("No access_token received");

    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, { accessToken, creator: { connected: true }, ts: Date.now() });

    res.cookie(COOKIE_NAME, sid, {
      signed: true,
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    console.log("🎉 OAUTH SUCCESS - Redirecting to frontend");
    return res.redirect("https://thesuccessmindset.club/daniapp/index.html?connected=1");

  } catch (err) {
    console.error("💥 FINAL ERROR IN CALLBACK");
    return res.status(500).send(`
      <h2>Connection Failed</h2>
      <p>Check Render Logs for full details.</p>
    `);
  }
});

// Add this temporary route to check env vars
app.get("/debug", (req, res) => {
  res.json({
    DANI_CLIENT_ID: DANI_CLIENT_ID ? "Present (" + DANI_CLIENT_ID.length + " chars)" : "MISSING",
    DANI_CLIENT_SECRET: DANI_CLIENT_SECRET ? "Present" : "MISSING",
    DANI_REDIRECT_URI: DANI_REDIRECT_URI || "MISSING",
    hasSessionSecret: !!SESSION_SECRET
  });
});

app.listen(PORT, () => {
  console.log("✅ SERVER STARTED WITH DEBUG LOGGING");
});
