require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer"); // Add this: npm install multer

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

// --- Multer for media uploads ---
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

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
app.use(express.json({ limit: "10mb", verify: rawBodySaver }));
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
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) webhookEvents.length = MAX_EVENTS;
}

// Keep your existing verifyFanvueSignature and normalizeWebhook functions
function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) return { ok: true, reason: "WEBHOOK_SECRET not set" };
  // ... (your original function - unchanged)
  const sig = (req.get("x-fanvue-signature") || "").trim();
  if (!sig) return { ok: false, reason: "missing signature" };
  // ... rest of your verify function
  return { ok: true, reason: "ok" }; // placeholder - keep your full version
}

function normalizeWebhook(body) {
  // ... your original function
  return { /* ... */ };
}

function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  const codeVerifier = crypto.randomBytes(32).toString("base64url")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  const codeChallenge = crypto.createHash("sha256")
    .update(codeVerifier).digest("base64url")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  oauthStates.set(state, { nonce, codeVerifier, ts: Date.now() });

  return { state, nonce, codeVerifier, codeChallenge };
}

// Token Exchange Helper
async function exchangeCodeForToken(clientId, clientSecret, code, redirectUri, codeVerifier) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  const resp = await axios.post("https://auth.fanvue.com/oauth2/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 20000,
  });
  return resp.data;
}

// =========================
// ROUTES
// =========================

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/health", (req, res) => res.send("ok"));

// === MVP OAuth ===
app.get("/oauth/start", (req, res) => { /* your original start logic */ });
app.get("/oauth/callback", async (req, res) => { /* your improved callback */ });

// === DaniApp OAuth ===
app.get("/daniapp/oauth/start", (req, res) => { /* your original start logic */ });
app.get("/daniapp/oauth/callback", async (req, res) => { /* your improved callback */ });

// =========================
// POSTING ENDPOINTS (NEW)
// =========================

app.post("/api/upload", upload.single("file"), async (req, res) => {
  const s = getSession(req);
  if (!s?.accessToken) return res.status(401).json({ error: "Not authenticated" });

  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  try {
    const form = new FormData();
    form.append("file", req.file.buffer, req.file.originalname);

    const uploadRes = await axios.post("https://api.fanvue.com/media", form, {
      headers: {
        Authorization: `Bearer ${s.accessToken}`,
        "X-Fanvue-API-Version": "2025-06-26",
        ...form.getHeaders(),
      },
      timeout: 60000,
    });

    return res.json({
      success: true,
      mediaId: uploadRes.data?.id || uploadRes.data?.mediaId,
      url: uploadRes.data?.url
    });
  } catch (err) {
    console.error("Media Upload Failed:", err?.response?.data || err.message);
    return res.status(500).json({ 
      error: "Media upload failed",
      details: err?.response?.data?.message || err.message 
    });
  }
});

app.post("/api/post", async (req, res) => {
  const s = getSession(req);
  if (!s?.accessToken) return res.status(401).json({ error: "Not authenticated" });

  try {
    const { caption, mediaIds = [], scheduledFor } = req.body;

    const payload = {
      content: caption || "",
      mediaIds: Array.isArray(mediaIds) ? mediaIds : [],
      visibility: "public",
      ...(scheduledFor && { scheduledFor })
    };

    const resp = await axios.post("https://api.fanvue.com/posts", payload, {
      headers: {
        Authorization: `Bearer ${s.accessToken}`,
        "X-Fanvue-API-Version": "2025-06-26",
        "Content-Type": "application/json",
      },
      timeout: 30000,
    });

    console.log("✅ Post created successfully");
    return res.json({ success: true, post: resp.data });
  } catch (err) {
    console.error("Create Post Failed:", {
      status: err?.response?.status,
      data: err?.response?.data
    });
    return res.status(500).json({
      error: "Post request failed",
      details: err?.response?.data?.message || err.message
    });
  }
});

// =========================
// Existing Routes (API, Webhooks, etc.)
// =========================

app.get("/api/me", (req, res) => { /* your original */ });
app.post("/api/logout", (req, res) => { /* your original */ });

// Webhooks...
app.get("/webhooks/fanvue", (req, res) => res.send("ok"));
app.post("/webhooks/fanvue", (req, res) => { /* your original webhook handler */ });

app.get("/api/events", (req, res) => { /* your original */ });
app.get("/api/events/last", (req, res) => { /* your original */ });
app.post("/api/events/clear", requireAdmin, (req, res) => { /* your original */ });

// SPA Fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("FANVUE + DANIAPP SERVER READY");
  console.log("=".repeat(60));
  console.log(`→ Dashboard: https://fanvue-proxy2.onrender.com/`);
  console.log(`→ DaniApp Post Endpoint: /api/post`);
});
