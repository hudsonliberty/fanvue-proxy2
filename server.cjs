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
const DANI_REDIRECT_URI =
  process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`;

const DANI_SCOPES =
  process.env.DANI_SCOPES ||
  "read:chat read:creator read:fan read:insights read:media read:self read:post write:chat write:creator write:media write:post read:tracking_links write:tracking_links read:agency write:agency";

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
    req.query.sid ||
    req.body?.sid ||
    "";

  return {
    sid,
    session: sid ? sessions.get(sid) : null
  };
}

function getMediaType(file) {
  if (file.mimetype.startsWith("video/")) return "video";
  if (file.mimetype.startsWith("audio/")) return "audio";
  if (file.mimetype.includes("pdf")) return "document";
  return "image";
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

function authHeaders(accessToken, extra = {}) {
  return {
    Authorization: `Bearer ${accessToken}`,
    "X-Fanvue-API-Version": FANVUE_API_VERSION,
    ...extra
  };
}

async function exchangeToken(code, codeVerifier) {
  const basicAuth = Buffer
    .from(`${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`)
    .toString("base64");

  const response = await axios.post(
    `${AUTH_BASE}/oauth2/token`,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: DANI_REDIRECT_URI,
      code_verifier: codeVerifier
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`
      },
      timeout: 30000
    }
  );

  return response.data;
}

async function getProfile(accessToken) {
  const response = await axios.get(`${API_BASE}/users/me`, {
    headers: authHeaders(accessToken),
    timeout: 30000
  });

  return response.data || {};
}

async function tryRequest(label, method, url, accessToken, data = null) {
  const response = await axios({
    method,
    url,
    data,
    headers: authHeaders(accessToken, {
      "Content-Type": "application/json"
    }),
    timeout: 30000,
    validateStatus: () => true
  });

  return {
    label,
    method,
    url,
    status: response.status,
    data: response.data
  };
}

async function createUploadSession(accessToken, profile, file) {
  const creatorUuid = profile?.uuid || "";

  const payloads = [
    {
      name: file.originalname,
      filename: file.originalname,
      mediaType: getMediaType(file),
      mimeType: file.mimetype,
      contentType: file.mimetype,
      size: file.size
    },
    {
      fileName: file.originalname,
      contentType: file.mimetype,
      type: getMediaType(file),
      size: file.size
    }
  ];

  const paths = [
    `${API_BASE}/media/uploads`,
    `${API_BASE}/uploads`,
    `${API_BASE}/media`,
    `${API_BASE}/creator/media/uploads`,
    `${API_BASE}/creators/media/uploads`,
    creatorUuid ? `${API_BASE}/creators/${creatorUuid}/media/uploads` : null
  ].filter(Boolean);

  const attempts = [];

  for (const url of paths) {
    for (const payload of payloads) {
      const result = await tryRequest("create_upload_session", "post", url, accessToken, payload);
      attempts.push(result);

      if (result.status >= 200 && result.status < 300) {
        return {
          ok: true,
          endpoint: url,
          response: result.data,
          attempts
        };
      }
    }
  }

  throw {
    stage: "create_upload_session",
    status: 404,
    details: {
      message: "No Fanvue upload-session endpoint accepted the request.",
      attempts
    }
  };
}

async function getSignedUploadUrl(accessToken, uploadEndpoint, uploadId) {
  const base = uploadEndpoint.replace(/\/$/, "");

  const urls = [
    `${base}/${uploadId}/parts/1/url`,
    `${base}/${uploadId}/url`,
    `${base}/${uploadId}/upload-url`,
    `${base}/${uploadId}/signed-url`
  ];

  const attempts = [];

  for (const url of urls) {
    const response = await axios.get(url, {
      headers: authHeaders(accessToken),
      timeout: 30000,
      validateStatus: () => true
    });

    attempts.push({
      url,
      status: response.status,
      data: response.data
    });

    if (response.status >= 200 && response.status < 300) {
      const signedUrl =
        response.data?.url ||
        response.data?.signedUrl ||
        response.data?.uploadUrl ||
        response.data?.data?.url ||
        response.data?.data?.signedUrl ||
        response.data?.data?.uploadUrl ||
        (typeof response.data === "string" ? response.data : "");

      if (signedUrl) {
        return {
          signedUrl,
          attempts
        };
      }
    }
  }

  throw {
    stage: "get_signed_upload_url",
    status: 404,
    details: {
      message: "No signed upload URL endpoint worked.",
      attempts
    }
  };
}

async function putFileToSignedUrl(signedUrl, file) {
  const response = await axios.put(signedUrl, file.buffer, {
    headers: {
      "Content-Type": file.mimetype,
      "Content-Length": file.size
    },
    timeout: 120000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    validateStatus: () => true
  });

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "s3_put_upload",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.headers.etag || response.headers.ETag || "";
}

async function completeUploadSession(accessToken, uploadEndpoint, uploadId, etag) {
  const base = uploadEndpoint.replace(/\/$/, "");

  const urls = [
    `${base}/${uploadId}/complete`,
    `${base}/${uploadId}`
  ];

  const payloads = [
    etag ? { parts: [{ partNumber: 1, etag }] } : { parts: [] },
    etag ? { parts: [{ PartNumber: 1, ETag: etag }] } : { parts: [] },
    {}
  ];

  const attempts = [];

  for (const url of urls) {
    for (const payload of payloads) {
      const response = await axios({
        method: url.endsWith("/complete") ? "post" : "patch",
        url,
        data: payload,
        headers: authHeaders(accessToken, {
          "Content-Type": "application/json"
        }),
        timeout: 30000,
        validateStatus: () => true
      });

      attempts.push({
        url,
        status: response.status,
        data: response.data
      });

      if (response.status >= 200 && response.status < 300) {
        return {
          response: response.data,
          attempts
        };
      }
    }
  }

  throw {
    stage: "complete_upload_session",
    status: 404,
    details: {
      message: "No complete-upload endpoint worked.",
      attempts
    }
  };
}

async function uploadMediaFanvue(accessToken, profile, file) {
  const startResult = await createUploadSession(accessToken, profile, file);
  const start = startResult.response;

  const uploadId =
    start?.uploadId ||
    start?.id ||
    start?.uuid ||
    start?.data?.uploadId ||
    start?.data?.id ||
    start?.data?.uuid;

  const mediaUuid =
    start?.mediaUuid ||
    start?.uuid ||
    start?.id ||
    start?.media?.uuid ||
    start?.data?.mediaUuid ||
    start?.data?.uuid ||
    start?.data?.id ||
    start?.data?.media?.uuid;

  if (!uploadId) {
    throw {
      stage: "create_upload_session",
      status: 500,
      details: {
        message: "Upload session succeeded but no uploadId was found.",
        response: startResult
      }
    };
  }

  const signedResult = await getSignedUploadUrl(
    accessToken,
    startResult.endpoint,
    uploadId
  );

  const etag = await putFileToSignedUrl(signedResult.signedUrl, file);

  const completeResult = await completeUploadSession(
    accessToken,
    startResult.endpoint,
    uploadId,
    etag
  );

  const complete = completeResult.response;

  const finalMediaUuid =
    mediaUuid ||
    complete?.mediaUuid ||
    complete?.uuid ||
    complete?.id ||
    complete?.media?.uuid ||
    complete?.data?.mediaUuid ||
    complete?.data?.uuid ||
    complete?.data?.id ||
    complete?.data?.media?.uuid;

  if (!finalMediaUuid) {
    throw {
      stage: "complete_upload_session",
      status: 500,
      details: {
        message: "Upload completed but no media UUID was found.",
        startResult,
        completeResult
      }
    };
  }

  return {
    mediaUuid: finalMediaUuid,
    uploadId,
    uploadEndpoint: startResult.endpoint,
    start,
    complete
  };
}

async function createPost(accessToken, profile, payload) {
  const creatorUuid = profile?.uuid || "";

  const urls = [
    `${API_BASE}/posts`,
    `${API_BASE}/creator/posts`,
    `${API_BASE}/creators/posts`,
    creatorUuid ? `${API_BASE}/creators/${creatorUuid}/posts` : null
  ].filter(Boolean);

  const attempts = [];

  for (const url of urls) {
    const response = await axios.post(url, payload, {
      headers: authHeaders(accessToken, {
        "Content-Type": "application/json"
      }),
      timeout: 30000,
      validateStatus: () => true
    });

    attempts.push({
      url,
      status: response.status,
      data: response.data
    });

    if (response.status >= 200 && response.status < 300) {
      return {
        endpoint: url,
        response: response.data,
        attempts
      };
    }
  }

  throw {
    stage: "create_post",
    status: 404,
    details: {
      message: "No post endpoint accepted the request.",
      payload,
      attempts
    }
  };
}

app.get("/", (req, res) => {
  res.send("DaniApp Fanvue Server Running");
});

app.get("/health", (req, res) => {
  res.send("ok");
});

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "daniapp-upload-endpoint-discovery-20260524",
    sessions: sessions.size,
    states: oauthStates.size,
    apiBase: API_BASE
  });
});

app.get("/daniapp/debug/full", (req, res) => {
  const { sid, session } = getSession(req);

  res.json({
    ok: true,
    sidPresent: !!sid,
    sessionExists: !!session,
    connected: !!session?.accessToken,
    profile: session?.profile || null,
    sessions: sessions.size
  });
});

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
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(`OAuth Error: ${error}`);
    }

    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    const stored = oauthStates.get(state);

    if (!stored) {
      return res.status(400).send("Invalid state");
    }

    oauthStates.delete(state);

    const tokens = await exchangeToken(code, stored.codeVerifier);
    const profile = await getProfile(tokens.access_token);

    const sid = makeSession({
      app: "daniapp",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || "",
      profile
    });

    const name = encodeURIComponent(getName(profile));
    const handle = encodeURIComponent(getHandle(profile));
    const avatar = encodeURIComponent(getAvatar(profile));

    res.redirect(
      `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("Callback failed:", err?.response?.data || err.message);
    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?error=oauth_failed`);
  }
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);

    if (!session?.accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue is not connected. Reconnect Fanvue first."
      });
    }

    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No media file"
      });
    }

    const caption = String(req.body.caption || "").trim();
    const audience = req.body.audience || "followers-and-subscribers";
    const priceNumber = Number(req.body.price || 0);

    const uploadResult = await uploadMediaFanvue(
      session.accessToken,
      session.profile,
      req.file
    );

    const postPayload = {
      audience,
      visibility: audience,
      text: caption,
      caption,
      mediaUuids: [uploadResult.mediaUuid],
      media: [uploadResult.mediaUuid]
    };

    if (priceNumber > 0) {
      postPayload.price = priceNumber;
    }

    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      postPayload.publishAt = new Date(req.body.scheduleTime).toISOString();
      postPayload.scheduleTime = req.body.scheduleTime;
    }

    const post = await createPost(
      session.accessToken,
      session.profile,
      postPayload
    );

    res.json({
      ok: true,
      message: "Post published successfully.",
      mediaUuid: uploadResult.mediaUuid,
      upload: uploadResult,
      post
    });
  } catch (err) {
    console.error("Upload/Post Error:", err);

    res.status(500).json({
      ok: false,
      stage: err.stage || "unknown",
      status: err.status || 500,
      details: err.details || err.message || err
    });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);

  if (sid) {
    sessions.delete(sid);
  }

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("DANIAPP FANVUE SERVER READY - UPLOAD ENDPOINT DISCOVERY");
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log(`Debug: ${BASE_URL}/daniapp/debug/full`);
});
