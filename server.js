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
const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const COOKIE_NAME = "fanvue_oauth";
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me-long-random-string").trim();
const FANVUE_API_VERSION = "2025-06-26";

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

async function exchangeToken(code, codeVerifier) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: DANI_CLIENT_ID,
    client_secret: DANI_CLIENT_SECRET,
    code: code,
    redirect_uri: DANI_REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  console.log("🔄 Token exchange with redirect_uri:", DANI_REDIRECT_URI);

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

// Keep all your other helper functions (getMediaType, uploadMediaAndCreatePost, etc.) unchanged
// ... paste them here from your original code ...

// =========================
// DANIAPP OAUTH
// =========================
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing OAuth credentials");
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

  console.log("🚀 OAuth Start:", authUrl.toString());
  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  console.log("📥 CALLBACK HIT:", req.query);

  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error("Fanvue Error:", error, error_description);
    return res.status(400).send(`Fanvue Error: ${error}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state");

  oauthStates.delete(state);

  try {
    const tokenData = await exchangeToken(code, st.codeVerifier);
    const accessToken = tokenData.access_token;

    if (!accessToken) throw new Error("No access_token received");

    console.log("✅ Token exchange successful");

    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, { accessToken, connected: true, ts: Date.now() });

    setSessionCookie(res, sid);

    console.log("🎉 Session created successfully");
    return res.redirect("https://thesuccessmindset.club/daniapp/index.html?connected=1");

  } catch (err) {
    console.error("❌ TOKEN EXCHANGE FAILED:", err?.response?.data || err.message);
    return res.status(500).send("OAuth failed. Check Render logs.");
  }
});

// POST ROUTE
app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  console.log("📨 POST REQUEST - Cookies present:", !!req.signedCookies[COOKIE_NAME]);

  const s = getSession(req);
  if (!s || !s.accessToken) {
    return res.status(401).json({
      ok: false,
      error: "Fanvue is not connected. Reconnect Fanvue first."
    });
  }

  if (!req.file) return res.status(400).json({ ok: false, error: "No media file" });

  try {
    const result = await uploadMediaAndCreatePost({
      accessToken: s.accessToken,
      file: req.file,
      caption: String(req.body.caption || "").trim(),
      audience: normalizeAudience(req.body.audience),
      price: req.body.price,
      postNow: req.body.postNow === "true",
      scheduleTime: req.body.scheduleTime
    });

    return res.json({ ok: true, result });
  } catch (err) {
    console.error("Post failed:", err.message);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// Debug route
app.get("/debug", (req, res) => {
  res.json({
    status: "ok",
    hasSessionCookie: !!req.signedCookies[COOKIE_NAME],
    activeSessions: sessions.size
  });
});

// Add your bulk-post and other routes here...

app.listen(PORT, () => {
  console.log("Server ready on port", PORT);
});
