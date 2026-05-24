require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL || "https://fanvue-proxy2.onrender.com";
const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

const AUTH_BASE = process.env.OAUTH_ISSUER_BASE_URL || "https://auth.fanvue.com";
const API_BASE = process.env.API_BASE_URL || "https://api.fanvue.com";
const FANVUE_API_VERSION = "2025-06-26";

const DANI_CLIENT_ID = process.env.DANI_CLIENT_ID || "";
const DANI_CLIENT_SECRET = process.env.DANI_CLIENT_SECRET || "";
const DANI_REDIRECT_URI = process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`;
const DANI_SCOPES = process.env.DANI_SCOPES || "read:chat read:creator read:fan read:insights read:media read:self read:post write:chat write:creator write:media write:post read:tracking_links write:tracking_links read:agency write:agency";

const sessions = new Map();
const oauthStates = new Map();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

app.set("trust proxy", true);

app.use(cors({ origin: true, credentials: true, allowedHeaders: ["Content-Type", "x-dani-session"] }));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ====================== HELPERS ======================
function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  oauthStates.set(state, { codeVerifier, created: Date.now() });
  return { state, codeVerifier, codeChallenge };
}

function makeSession(data) {
  const sid = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, { ...data, created: Date.now() });
  return sid;
}

function getSession(req) {
  const sid = req.get("x-dani-session") || req.query.sid || req.body?.sid || "";
  return { sid, session: sid ? sessions.get(sid) : null };
}

// ====================== FANVUE FUNCTIONS ======================
async function putFileToSignedUrl(signedUrl, file) {
  const res = await axios.put(signedUrl, file.buffer, {
    headers: { "Content-Type": file.mimetype, "Content-Length": file.size },
    timeout: 120000,
    validateStatus: () => true
  });
  if (res.status >= 400) throw { stage: "s3_put", status: res.status };
  return res.headers.etag || res.headers.ETag || "";
}

async function createUploadSession(accessToken, file) {
  const res = await axios.post(`${API_BASE}/creators/media/uploads`, {
    name: file.originalname,
    filename: file.originalname,
    mediaType: file.mimetype.startsWith("video/") ? "video" : "image"
  }, {
    headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION, "Content-Type": "application/json" },
    validateStatus: () => true
  });
  if (res.status >= 400) throw { stage: "create_upload_session", status: res.status, details: res.data };
  return res.data;
}

async function getSignedUploadUrl(accessToken, uploadId) {
  const res = await axios.get(`${API_BASE}/creators/media/uploads/${uploadId}/parts/1/url`, {
    headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION },
    validateStatus: () => true
  });
  if (res.status >= 400) throw { stage: "get_signed_url", status: res.status };
  return res.data?.url || res.data;
}

async function completeUploadSession(accessToken, uploadId, etag) {
  const res = await axios.patch(`${API_BASE}/creators/media/uploads/${uploadId}`, {
    parts: [{ partNumber: 1, etag }]
  }, {
    headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION, "Content-Type": "application/json" },
    validateStatus: () => true
  });
  if (res.status >= 400) throw { stage: "complete_upload", status: res.status };
  return res.data;
}

// ====================== ROUTES ======================
app.get("/", (req, res) => res.send("DaniApp Fanvue OK"));
app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "daniapp-final-20250524",
    sessions: sessions.size
  });
});

app.get("/daniapp/debug/full", (req, res) => {
  const { sid, session } = getSession(req);
  res.json({
    ok: true,
    sidPresent: !!sid,
    sessionExists: !!session,
    connected: !!session?.accessToken,
    profile: session?.profile || null
  });
});

// OAuth Start
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET) return res.status(503).send("Missing OAuth credentials");
  const pkce = createPkceState();
  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", DANI_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

// OAuth Callback
app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send(`Error: ${error}`);
    if (!code || !state) return res.status(400).send("Missing code or state");

    const stored = oauthStates.get(state);
    if (!stored) return res.status(400).send("Invalid state");

    oauthStates.delete(state);

    const basicAuth = Buffer.from(`${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`).toString("base64");

    const tokenResponse = await axios.post(`${AUTH_BASE}/oauth2/token`, new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: DANI_REDIRECT_URI,
      code_verifier: stored.codeVerifier
    }), {
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basicAuth}` }
    });

    const tokens = tokenResponse.data;

    // Get profile
    const profileRes = await axios.get(`${API_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}`, "X-Fanvue-API-Version": FANVUE_API_VERSION }
    });

    const sid = makeSession({
      app: "daniapp",
      accessToken: tokens.access_token,
      profile: profileRes.data
    });

    const name = encodeURIComponent(profileRes.data.displayName || "Dani Richmond");
    const handle = encodeURIComponent("@" + (profileRes.data.handle || "").replace("@", ""));
    const avatar = encodeURIComponent(profileRes.data.avatarUrl || "");

    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`);
  } catch (err) {
    console.error("Callback error:", err?.response?.data || err.message);
    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?error=1`);
  }
});

// Post Endpoint
app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ ok: false, error: "Not connected" });
    if (!req.file) return res.status(400).json({ ok: false, error: "No file" });

    const uploadResult = await createUploadSession(session.accessToken, req.file);
    const mediaUuid = uploadResult.mediaUuid || uploadResult.uuid || uploadResult.id;
    const uploadId = uploadResult.uploadId || uploadResult.id;

    const signedUrl = await getSignedUploadUrl(session.accessToken, uploadId);
    const etag = await putFileToSignedUrl(signedUrl, req.file);
    await completeUploadSession(session.accessToken, uploadId, etag);

    const postPayload = {
      audience: "followers-and-subscribers",
      text: req.body.caption || "",
      mediaUuids: [mediaUuid]
    };

    const post = await axios.post(`${API_BASE}/creators/posts`, postPayload, {
      headers: { Authorization: `Bearer ${session.accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION, "Content-Type": "application/json" }
    });

    res.json({ ok: true, post: post.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.stage || err.message });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("🚀 DANIAPP FANVUE SERVER - FINAL BUILD");
  console.log(`→ ${BASE_URL}/env-check`);
});
