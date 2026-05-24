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

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }
});

app.set("trust proxy", true);

app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ["Content-Type", "x-dani-session"],
  methods: ["GET", "POST", "OPTIONS"]
}));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ====================== HELPERS ======================
function createPkceState(appName) {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  oauthStates.set(state, { appName, codeVerifier, created: Date.now() });
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

function getMediaType(file) {
  if (file.mimetype.startsWith("video/")) return "video";
  if (file.mimetype.startsWith("audio/")) return "audio";
  if (file.mimetype.includes("pdf")) return "document";
  return "image";
}

// ====================== FANVUE UPLOAD FUNCTIONS ======================
async function createUploadSession(accessToken, file) {
  const response = await axios.post(`${API_BASE}/creators/media/uploads`, {
    name: file.originalname,
    filename: file.originalname,
    mediaType: getMediaType(file)
  }, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "create_upload_session",
      status: response.status,
      details: response.data
    };
  }
  return response.data;
}

async function getSignedUploadUrl(accessToken, uploadId) {
  const response = await axios.get(`${API_BASE}/creators/media/uploads/${uploadId}/parts/1/url`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    },
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "get_signed_upload_url", status: response.status, details: response.data };
  }
  return response.data?.url || response.data?.signedUrl || response.data;
}

async function putFileToSignedUrl(signedUrl, file) {
  const response = await axios.put(signedUrl, file.buffer, {
    headers: {
      "Content-Type": file.mimetype,
      "Content-Length": file.size
    },
    timeout: 120000,
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "s3_put_upload", status: response.status, details: response.data };
  }
  return response.headers.etag || response.headers.ETag || "";
}

async function completeUploadSession(accessToken, uploadId, etag) {
  const response = await axios.patch(`${API_BASE}/creators/media/uploads/${uploadId}`, {
    parts: [{ partNumber: 1, etag }]
  }, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "complete_upload_session", status: response.status, details: response.data };
  }
  return response.data;
}

async function createPost(accessToken, payload) {
  const response = await axios.post(`${API_BASE}/creators/posts`, payload, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "create_post", status: response.status, details: response.data };
  }
  return response.data;
}

// ====================== MAIN UPLOAD FUNCTION ======================
async function uploadMediaFanvue(accessToken, file) {
  const start = await createUploadSession(accessToken, file);
  const mediaUuid = start.mediaUuid || start.uuid || start.id || start.data?.mediaUuid;
  const uploadId = start.uploadId || start.id || start.data?.uploadId || start.data?.id;

  if (!mediaUuid || !uploadId) {
    throw { stage: "create_upload_session", status: 500, details: "Missing mediaUuid or uploadId" };
  }

  const signedUrl = await getSignedUploadUrl(accessToken, uploadId);
  const etag = await putFileToSignedUrl(signedUrl, file);
  await completeUploadSession(accessToken, uploadId, etag);

  return { mediaUuid, uploadId };
}

// ====================== ROUTES ======================
app.get("/", (req, res) => res.send("DaniApp Fanvue Server Running"));
app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "daniapp-complete-final-20250524",
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

// OAuth Routes
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET) {
    return res.status(503).send("Missing OAuth credentials");
  }
  const pkce = createPkceState("daniapp");
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

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send(`OAuth Error: ${error}`);
    if (!code || !state) return res.status(400).send("Missing code or state");

    const stored = oauthStates.get(state);
    if (!stored) return res.status(400).send("Invalid state");

    oauthStates.delete(state);

    const basicAuth = Buffer.from(`${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`).toString("base64");

    const tokenRes = await axios.post(`${AUTH_BASE}/oauth2/token`, new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: DANI_REDIRECT_URI,
      code_verifier: stored.codeVerifier
    }), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`
      }
    });

    const tokens = tokenRes.data;
    const profileRes = await axios.get(`${API_BASE}/users/me`, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      }
    });

    const sid = makeSession({
      app: "daniapp",
      accessToken: tokens.access_token,
      profile: profileRes.data
    });

    const name = encodeURIComponent(profileRes.data.displayName || "Dani Richmond");
    const handle = encodeURIComponent(`@${(profileRes.data.handle || "").replace("@", "")}`);
    const avatar = encodeURIComponent(profileRes.data.avatarUrl || "");

    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`);
  } catch (err) {
    console.error("Callback failed:", err?.response?.data || err.message);
    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?error=oauth_failed`);
  }
});

// POST ROUTE - This is the one that was failing
app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ ok: false, error: "Not connected" });
    if (!req.file) return res.status(400).json({ ok: false, error: "No media file" });

    console.log(`📤 Uploading: ${req.file.originalname} (${req.file.mimetype})`);

    const uploadResult = await uploadMediaFanvue(session.accessToken, req.file);

    const postPayload = {
      audience: req.body.audience || "followers-and-subscribers",
      text: String(req.body.caption || "").trim(),
      mediaUuids: [uploadResult.mediaUuid]
    };

    if (Number(req.body.price) > 0) postPayload.price = Number(req.body.price);

    const post = await createPost(session.accessToken, postPayload);

    res.json({ ok: true, message: "Post published successfully!", post });
  } catch (err) {
    console.error("❌ Upload/Post Error:", err);
    res.status(500).json({
      ok: false,
      stage: err.stage || "unknown",
      status: err.status || 500,
      details: err.details || err.message
    });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("🚀 DANIAPP FANVUE SERVER - COMPLETE FINAL BUILD");
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log(`Debug: ${BASE_URL}/daniapp/debug/full`);
});
