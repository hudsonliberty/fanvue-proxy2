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

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || `${BASE_URL}/oauth/callback`;
const OAUTH_SCOPES = process.env.OAUTH_SCOPES || "read:self read:chat read:creator read:fan write:chat";

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
  allowedHeaders: ["Content-Type", "x-dani-session", "x-mvp-session"],
  methods: ["GET", "POST", "OPTIONS"]
}));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

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
  const sid =
    req.get("x-dani-session") ||
    req.get("x-mvp-session") ||
    req.query.sid ||
    "";

  return {
    sid,
    session: sid ? sessions.get(sid) : null
  };
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

// ==================== NEW UPLOAD FUNCTIONS ====================

async function createUploadSession(accessToken, file) {
  const response = await axios.post(
    `${API_BASE}/media/uploads`,
    {
      filename: file.originalname,
      mimeType: file.mimetype,
      size: file.size
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "create_upload_session",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data;
}

async function getSignedUploadUrl(accessToken, uploadId) {
  const response = await axios.post(
    `${API_BASE}/media/uploads/${uploadId}/url`,
    {},
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "get_signed_upload_url",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data.url;
}

async function completeUploadSession(accessToken, uploadId) {
  const response = await axios.post(
    `${API_BASE}/media/uploads/${uploadId}/complete`,
    {},
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "complete_upload_session",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data;
}

async function uploadMediaFanvue(accessToken, file) {
  const start = await createUploadSession(accessToken, file);

  const uploadId =
    start.uploadId ||
    start.id ||
    start.uuid;

  const mediaUuid =
    start.mediaUuid ||
    start.media?.uuid ||
    start.uuid;

  if (!uploadId) {
    throw {
      stage: "create_upload_session",
      details: start
    };
  }

  const signedUrl = await getSignedUploadUrl(accessToken, uploadId);

  await axios.put(
    signedUrl,
    file.buffer,
    {
      headers: {
        "Content-Type": file.mimetype
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      validateStatus: () => true
    }
  );

  await completeUploadSession(accessToken, uploadId);

  return {
    mediaUuid,
    uploadId
  };
}

// ==================== END OF NEW UPLOAD FUNCTIONS ====================

async function createUserPost(accessToken, payload) {
  const response = await axios.post(
    `${API_BASE}/creator/posts`,
    payload,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      },
      timeout: 30000,
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "create_post",
      status: response.status,
      details: response.data,
      payloadSent: payload
    };
  }

  return response.data;
}

setInterval(() => {
  const now = Date.now();

  for (const [state, value] of oauthStates.entries()) {
    if (now - value.created > 15 * 60 * 1000) oauthStates.delete(state);
  }

  for (const [sid, value] of sessions.entries()) {
    if (now - value.created > 30 * 24 * 60 * 60 * 1000) sessions.delete(sid);
  }
}, 60 * 1000);

app.get("/", (req, res) => {
  res.send(`
    <body style="background:#111;color:white;font-family:Arial;padding:40px">
      <h1>Fanvue Two-App Server Running</h1>
      <p><a style="color:#ff1493" href="/oauth/start">MidKnight Login</a></p>
      <p><a style="color:#ff1493" href="/daniapp/oauth/start">DaniApp Login</a></p>
      <p><a style="color:#ff1493" href="/env-check">Env Check</a></p>
    </body>
  `);
});

app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "two-app-creator-upload-session-v2",
    midknight: { client: !!OAUTH_CLIENT_ID },
    daniapp: { client: !!DANI_CLIENT_ID },
    endpoints: {
      createUploadSession: `${API_BASE}/media/uploads`,
      getSignedUrl: `${API_BASE}/media/uploads/:uploadId/url`,
      completeUpload: `${API_BASE}/media/uploads/:uploadId/complete`
    },
    sessions: sessions.size,
    states: oauthStates.size
  });
});

// ... (all OAuth routes remain unchanged) ...

app.get("/oauth/start", (req, res) => { /* unchanged */ });
app.get("/oauth/callback", async (req, res) => { /* unchanged */ });
app.get("/daniapp/oauth/start", (req, res) => { /* unchanged */ });
app.get("/daniapp/oauth/callback", async (req, res) => { /* unchanged */ });
app.get("/daniapp/debug/full", (req, res) => { /* unchanged */ });

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);

    if (!session || session.app !== "daniapp" || !session.accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue is not connected. Reconnect Fanvue first."
      });
    }

    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No media uploaded"
      });
    }

    const uploadResult = await uploadMediaFanvue(
      session.accessToken,
      req.file
    );

    const priceNumber = Number(req.body.price || 0);

    const postPayload = {
      audience: req.body.audience || "followers-and-subscribers",
      text: String(req.body.caption || "").trim(),
      mediaUuids: [uploadResult.mediaUuid]
    };

    if (priceNumber > 0) {
      postPayload.price = priceNumber;
    }

    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      postPayload.publishAt = new Date(req.body.scheduleTime).toISOString();
    }

    const post = await createUserPost(
      session.accessToken,
      postPayload
    );

    return res.json({
      ok: true,
      message: req.body.postNow === "true" ? "Posted successfully" : "Scheduled successfully",
      mediaUuid: uploadResult.mediaUuid,
      upload: uploadResult,
      post
    });

  } catch (err) {
    console.error("Dani post failed:", err);
    return res.status(500).json({
      ok: false,
      error: "Fanvue post failed",
      stage: err.stage || "unknown",
      status: err.status || 500,
      details: err.details || err.message || err
    });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

app.post("/daniapp/api/bulk-post", (req, res) => {
  res.json({ ok: true, message: "Bulk route alive" });
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("TWO APP FANVUE SERVER READY - SIMPLE UPLOAD BUILD");
  console.log(`MidKnight OAuth: ${BASE_URL}/oauth/start`);
  console.log(`DaniApp OAuth: ${BASE_URL}/daniapp/oauth/start`);
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log("============================================================");
});
