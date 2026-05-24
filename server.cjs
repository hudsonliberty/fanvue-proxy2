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

// ====================== HELPER FUNCTIONS ======================

function createPkceState(appName) {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  oauthStates.set(state, {
    appName,
    nonce,
    codeVerifier,
    created: Date.now()
  });

  return { state, nonce, codeVerifier, codeChallenge };
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

function getName(profile) {
  return profile?.displayName || profile?.name || profile?.username || profile?.handle || "Fanvue Creator";
}

function getHandle(profile) {
  const raw = profile?.handle || profile?.username || "";
  return raw ? "@" + String(raw).replace(/^@/, "") : "";
}

function getAvatar(profile) {
  return profile?.avatarUrl || profile?.avatar_url || profile?.avatarUri?.url || profile?.avatarUriSm?.url || "";
}

function getMediaType(file) {
  if (file.mimetype.startsWith("video/")) return "video";
  if (file.mimetype.startsWith("audio/")) return "audio";
  if (file.mimetype.includes("pdf")) return "document";
  return "image";
}

// ====================== UPLOAD HELPERS ======================

async function putFileToSignedUrl(signedUrl, file) {
  const response = await axios.put(signedUrl, file.buffer, {
    headers: { "Content-Type": file.mimetype, "Content-Length": file.size },
    timeout: 120000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "s3_put_upload", status: response.status, details: response.data };
  }
  return response.headers.etag || response.headers.ETag || "";
}

// ====================== FIXED FANVUE ENDPOINTS ======================

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
    timeout: 30000,
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "create_upload_session", status: response.status, details: response.data };
  }
  return response.data;
}

async function getSignedUploadUrl(accessToken, uploadId, partNumber) {
  const response = await axios.get(
    `${API_BASE}/creators/media/uploads/${uploadId}/parts/${partNumber}/url`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      timeout: 30000,
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "get_signed_upload_url", status: response.status, details: response.data };
  }
  return response.data?.url || response.data?.signedUrl || response.data?.uploadUrl || response.data;
}

async function completeUploadSession(accessToken, uploadId, parts) {
  const response = await axios.patch(`${API_BASE}/creators/media/uploads/${uploadId}`, { parts }, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    timeout: 30000,
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
    timeout: 30000,
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw { stage: "create_post", status: response.status, details: response.data, payloadSent: payload };
  }
  return response.data;
}

// ====================== MAIN UPLOAD FUNCTION ======================

async function uploadMediaFanvue(accessToken, file) {
  const start = await createUploadSession(accessToken, file);

  const mediaUuid = start.mediaUuid || start.uuid || start.media?.uuid || start.data?.mediaUuid || start.data?.uuid;
  const uploadId = start.uploadId || start.id || start.data?.uploadId || start.data?.id;

  if (!mediaUuid || !uploadId) {
    throw { stage: "create_upload_session", status: 500, details: { error: "Missing mediaUuid or uploadId", response: start } };
  }

  const partNumber = 1;
  const signedUrl = await getSignedUploadUrl(accessToken, uploadId, partNumber);

  if (!signedUrl) throw { stage: "get_signed_upload_url", status: 500, details: "No signed URL returned" };

  const etag = await putFileToSignedUrl(signedUrl, file);

  const complete = await completeUploadSession(accessToken, uploadId, etag ? [{ partNumber, etag }] : []);

  return { mediaUuid, uploadId, complete, start };
}

// ====================== ROUTES ======================

app.get("/", (req, res) => res.send("DaniApp Fanvue server running"));
app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "daniapp-creators-plural-v2",
    daniapp: {
      client: !!DANI_CLIENT_ID,
      redirect: DANI_REDIRECT_URI,
      scopes: DANI_SCOPES
    },
    endpoints: {
      createUploadSession: `${API_BASE}/creators/media/uploads`,
      uploadPartUrl: `${API_BASE}/creators/media/uploads/:uploadId/parts/:partNumber/url`,
      completeUpload: `${API_BASE}/creators/media/uploads/:uploadId`,
      createPost: `${API_BASE}/creators/posts`
    },
    sessions: sessions.size
  });
});

// === OAUTH ROUTES ===
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth environment variables.");
  }

  const pkce = createPkceState("daniapp");
  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", DANI_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) return res.status(400).send(`OAuth error: ${error} ${error_description || ""}`);
    if (!code || !state) return res.status(400).send("Missing code or state");

    const stored = oauthStates.get(state);
    if (!stored || stored.appName !== "daniapp") return res.status(400).send("Invalid state");

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
    let profile = {};

    try {
      profile = await axios.get(`${API_BASE}/users/me`, {
        headers: { Authorization: `Bearer ${tokens.access_token}`, "X-Fanvue-API-Version": FANVUE_API_VERSION }
      }).then(r => r.data);
    } catch (e) { console.error("Profile fetch failed", e.message); }

    const sid = makeSession({ app: "daniapp", accessToken: tokens.access_token, refreshToken: tokens.refresh_token || "", profile });

    const name = encodeURIComponent(getName(profile) || "Creator");
    const handle = encodeURIComponent(getHandle(profile) || "");
    const avatar = encodeURIComponent(getAvatar(profile) || "");

    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`);
  } catch (err) {
    console.error("OAuth callback error:", err?.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

// === POST ROUTE ===
app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ ok: false, error: "Fanvue not connected" });
    if (!req.file) return res.status(400).json({ ok: false, error: "No media uploaded" });

    const uploadResult = await uploadMediaFanvue(session.accessToken, req.file);

    const postPayload = {
      audience: req.body.audience || "followers-and-subscribers",
      text: String(req.body.caption || "").trim(),
      mediaUuids: [uploadResult.mediaUuid]
    };

    if (Number(req.body.price) > 0) postPayload.price = Number(req.body.price);
    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      postPayload.publishAt = new Date(req.body.scheduleTime).toISOString();
    }

    const post = await createPost(session.accessToken, postPayload);

    res.json({ ok: true, message: "Success", mediaUuid: uploadResult.mediaUuid, post });
  } catch (err) {
    console.error("Post failed:", err);
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
  console.log("============================================================");
  console.log("DANIAPP FANVUE SERVER READY - CREATORS FIXED v2");
  console.log(`OAuth Start → ${BASE_URL}/daniapp/oauth/start`);
  console.log(`Env Check → ${BASE_URL}/env-check`);
  console.log("============================================================");
});
