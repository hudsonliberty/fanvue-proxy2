Replace the entire server.cjs with this rebuilt version:

// server.cjs — Fanvue MVP + DaniApp OAuth + Single Post + Bulk Upload
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
const upload = multer({
  storage: multer.memoryStorage()
});
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
// --- Raw-body capture ---
function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}
// --- Middleware ---
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});
app.use(
  express.json({
    limit: "25mb",
    verify: rawBodySaver
  })
);
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
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
  return res.status(401).json({
    error: "Unauthorized"
  });
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
function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    path: "/"
  });
}
function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) {
    webhookEvents.length = MAX_EVENTS;
  }
}
function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto
    .randomBytes(32)
    .toString("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  oauthStates.set(state, {
    nonce,
    codeVerifier,
    ts: Date.now()
  });
  return {
    state,
    nonce,
    codeVerifier,
    codeChallenge
  };
}
function extractCreatorProfile(creator) {
  return {
    name:
      creator.displayName ||
      creator.name ||
      creator.username ||
      creator.handle ||
      creator.email ||
      "Fanvue Creator",
    handle: creator.handle
      ? `@${String(creator.handle).replace(/^@/, "")}`
      : "",
    avatar:
      creator.avatarUrl ||
      creator.avatar_url ||
      creator.avatarUri?.url ||
      creator.avatarUriSm?.url ||
      creator.avatarUriXs?.url ||
      creator.profilePictureUrl ||
      creator.profile_picture_url ||
      creator.imageUrl ||
      creator.image_url ||
      ""
  };
}
function getMediaType(mimetypeOrFilename) {
  const v = String(mimetypeOrFilename || "").toLowerCase();
  if (v.startsWith("video/") || /\.(mp4|mov|webm|m4v)$/i.test(v)) return "video";
  if (v.startsWith("audio/") || /\.(mp3|wav|m4a)$/i.test(v)) return "audio";
  if (v.startsWith("image/") || /\.(jpg|jpeg|png|webp|gif)$/i.test(v)) return "image";
  return "document";
}
function findSignedUrl(value) {
  if (!value) return "";
  if (typeof value === "string") {
    return value.startsWith("https://") ? value : "";
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findSignedUrl(item);
      if (found) return found;
    }
  }
  if (typeof value === "object") {
    const priorityKeys = [
      "url",
      "uploadUrl",
      "signedUrl",
      "presignedUrl",
      "href",
      "putUrl",
      "upload_url",
      "signed_url",
      "presigned_url"
    ];
    for (const key of priorityKeys) {
      const found = findSignedUrl(value[key]);
      if (found) return found;
    }
    for (const key of Object.keys(value)) {
      const found = findSignedUrl(value[key]);
      if (found) return found;
    }
  }
  return "";
}
function parseBool(value) {
  const v = String(value || "").trim().toLowerCase();
  return v === "true" || v === "yes" || v === "1" || v === "now";
}
function normalizeAudience(value) {
  const v = String(value || "").trim();
  if (v === "subscribers") return "subscribers";
  if (v === "followers-and-subscribers") return "followers-and-subscribers";
  return "followers-and-subscribers";
}
function parseBulkFile(file) {
  const name = file.originalname.toLowerCase();
  if (name.endsWith(".csv")) {
    return parse(file.buffer.toString("utf8"), {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });
  }
  if (name.endsWith(".xlsx") || name.endsWith(".xls")) {
    const workbook = XLSX.read(file.buffer, { type: "buffer" });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    return XLSX.utils.sheet_to_json(sheet, { defval: "" });
  }
  throw new Error("Only CSV, XLS, or XLSX files are supported.");
}
async function downloadMediaFromUrl(mediaUrl, filename) {
  const response = await axios.get(mediaUrl, {
    responseType: "arraybuffer",
    timeout: 120000,
    maxContentLength: Infinity,
    maxBodyLength: Infinity
  });
  const contentType = response.headers["content-type"] || "application/octet-stream";
  return {
    buffer: Buffer.from(response.data),
    mimetype: contentType,
    originalname: filename || path.basename(new URL(mediaUrl).pathname) || "media-file"
  };
}
async function waitForMediaReady(mediaUuid, fanvueHeaders) {
  const maxAttempts = 24;
  const delayMs = 5000;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const resp = await axios.get(
      `https://api.fanvue.com/media/${encodeURIComponent(mediaUuid)}`,
      {
        headers: fanvueHeaders,
        timeout: 30000,
        validateStatus: (status) => status >= 200 && status < 500
      }
    );
    console.log(
      "MEDIA STATUS:",
      JSON.stringify({
        mediaUuid,
        attempt,
        response: resp.data
      })
    );
    const status = resp.data?.status || "";
    if (status === "ready") {
      return resp.data;
    }
    if (status === "error") {
      throw new Error(`Fanvue media processing failed for ${mediaUuid}`);
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(`Media did not become ready in time: ${mediaUuid}`);
}
async function uploadMediaAndCreatePost({
  accessToken,
  file,
  caption,
  audience,
  price,
  postNow,
  scheduleTime
}) {
  const fanvueHeaders = {
    Authorization: `Bearer ${accessToken}`,
    "X-Fanvue-API-Version": FANVUE_API_VERSION
  };
  const uploadSession = await axios.post(
    "https://api.fanvue.com/media/uploads",
    {
      name: file.originalname,
      filename: file.originalname,
      mediaType: getMediaType(file.mimetype || file.originalname)
    },
    {
      headers: {
        ...fanvueHeaders,
        "Content-Type": "application/json"
      },
      timeout: 30000
    }
  );
  console.log("UPLOAD SESSION:", JSON.stringify(uploadSession.data));
  const mediaUuid = uploadSession.data.mediaUuid;
  const uploadId = uploadSession.data.uploadId;
  if (!mediaUuid || !uploadId) {
    throw new Error("Fanvue did not return mediaUuid/uploadId.");
  }
  const signedUrlResp = await axios.get(
    `https://api.fanvue.com/media/uploads/${encodeURIComponent(uploadId)}/parts/1/url`,
    {
      headers: fanvueHeaders,
      timeout: 30000
    }
  );
  console.log("SIGNED URL RESPONSE:", JSON.stringify(signedUrlResp.data));
  const signedUrl = findSignedUrl(signedUrlResp.data);
  if (!signedUrl) {
    throw new Error("Fanvue did not return a signed upload URL.");
  }
  const uploadPartResp = await axios.put(signedUrl, file.buffer, {
    headers: {
      "Content-Type": file.mimetype || "application/octet-stream"
    },
    timeout: 120000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    validateStatus: (status) => status >= 200 && status < 300
  });
  const etagRaw = uploadPartResp.headers.etag || uploadPartResp.headers.ETag || "";
  const etag = String(etagRaw).replace(/^"|"$/g, "");
  const completePayload = etag
    ? {
        parts: [
          {
            ETag: etag,
            PartNumber: 1
          }
        ]
      }
    : {
        parts: [
          {
            PartNumber: 1
          }
        ]
      };
  const completeResp = await axios.patch(
    `https://api.fanvue.com/media/uploads/${encodeURIComponent(uploadId)}`,
    completePayload,
    {
      headers: {
        ...fanvueHeaders,
        "Content-Type": "application/json"
      },
      timeout: 30000
    }
  );
  console.log("UPLOAD COMPLETE:", JSON.stringify(completeResp.data));
  const mediaReadyData = await waitForMediaReady(mediaUuid, fanvueHeaders);
  const postPayload = {
    text: caption,
    mediaUuids: [mediaUuid],
    audience
  };
  const priceNumber = Number(price || 0);
  if (priceNumber > 0) {
    postPayload.price = Math.round(priceNumber * 100);
  }
  if (!postNow && scheduleTime) {
    postPayload.publishAt = new Date(scheduleTime).toISOString();
  }
  console.log("POST PAYLOAD:", JSON.stringify(postPayload));
  const postResp = await axios.post("https://api.fanvue.com/posts", postPayload, {
    headers: {
      ...fanvueHeaders,
      "Content-Type": "application/json"
    },
    timeout: 30000,
    validateStatus: (status) => status >= 200 && status < 300
  });
  console.log("POST RESPONSE:", JSON.stringify(postResp.data));
  return {
    mediaUuid,
    uploadId,
    mediaReadyData,
    post: postResp.data
  };
}
function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) {
    return {
      ok: true,
      reason: "WEBHOOK_SECRET not set"
    };
  }
  const sig = (req.get("x-fanvue-signature") || "").trim();
  if (!sig) {
    return {
      ok: false,
      reason: "missing x-fanvue-signature"
    };
  }
  const parts = Object.fromEntries(
    sig.split(",").map((kv) => {
      const [k, v] = kv.split("=");
      return [
        String(k || "").trim(),
        String(v || "").trim()
      ];
    })
  );
  const t = parts.t;
  const v0 = parts.v0;
  if (!t || !v0) {
    return {
      ok: false,
      reason: "signature missing t or v0"
    };
  }
  const raw = req.rawBody || "";
  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(`${t}.${raw}`, "utf8")
    .digest("hex");
  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(v0, "hex");
  if (a.length !== b.length) {
    return {
      ok: false,
      reason: "signature length mismatch"
    };
  }
  const ok = crypto.timingSafeEqual(a, b);
  return {
    ok,
    reason: ok ? "ok" : "signature mismatch"
  };
}
function normalizeWebhook(body) {
  const sender = body?.sender || {};
  const senderName =
    sender?.displayName ||
    sender?.handle ||
    "";
  const senderHandle = sender?.handle
    ? `@${String(sender.handle).replace(/^@/, "")}`
    : "";
  const senderAvatar =
    sender?.avatarUri?.url ||
    sender?.avatarUriSm?.url ||
    sender?.avatarUriXs?.url ||
    "";
  const text =
    body?.data?.text ||
    body?.text ||
    body?.message ||
    "";
  const messageUuid =
    body?.messageUuid ||
    body?.data?.id ||
    body?.id ||
    "";
  const recipientUuid =
    body?.recipientUuid ||
    body?.recipient?.uuid ||
    body?.data?.recipientUuid ||
    "";
  const type =
    body?.type ||
    body?.event ||
    "unknown";
  return {
    type,
    messageUuid,
    recipientUuid,
    senderName,
    senderHandle,
    senderAvatar,
    text
  };
}
// --- Startup log ---
console.log("=".repeat(60));
console.log("FANVUE MVP + DANIAPP STARTING");
console.log("=".repeat(60));
console.log(`NODE_ENV: ${process.env.NODE_ENV || "development"}`);
console.log(`CLIENT_ID present: ${!!CLIENT_ID}`);
console.log(`CLIENT_SECRET present: ${!!CLIENT_SECRET}`);
console.log(`DANI_CLIENT_ID present: ${!!DANI_CLIENT_ID}`);
console.log(`DANI_CLIENT_SECRET present: ${!!DANI_CLIENT_SECRET}`);
console.log(`DANI_REDIRECT_URI present: ${!!DANI_REDIRECT_URI}`);
console.log(`ADMIN_TOKEN present: ${!!ADMIN_TOKEN}`);
console.log(`WEBHOOK_SECRET present: ${!!WEBHOOK_SECRET}`);
console.log(`PORT: ${PORT}`);
console.log("=".repeat(60));
// --- Frontend routes ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
app.get("/health", (req, res) => {
  res.status(200).send("ok");
});
// =========================
// ORIGINAL MVP OAUTH START
// =========================
app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res
      .status(503)
      .send("Missing CLIENT_ID / CLIENT_SECRET in environment.");
  }
  const pkce = createPkceState();
  const redirectUri = `${baseUrl(req)}/oauth/callback`;
  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set(
    "scope",
    "openid offline_access read:self read:fan read:insights"
  );
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  return res.redirect(authUrl.toString());
});
// =========================
// ORIGINAL MVP OAUTH CALLBACK
// =========================
app.get("/oauth/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) {
    return res.status(400).send("Missing code/state");
  }
  const st = oauthStates.get(state);
  if (!st) {
    return res.status(400).send("Invalid/expired state. Restart login.");
  }
  oauthStates.delete(state);
  try {
    const redirectUri = `${baseUrl(req)}/oauth/callback`;
    const basicAuth = Buffer
      .from(`${CLIENT_ID}:${CLIENT_SECRET}`)
      .toString("base64");
    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri,
        code_verifier: st.codeVerifier
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`
        },
        timeout: 20000
      }
    );
    const accessToken = tokenResp.data.access_token;
    if (!accessToken) {
      throw new Error("No access_token returned");
    }
    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    };
    const profileResp = await axios.get("https://api.fanvue.com/users/me", {
      headers: apiHeaders,
      timeout: 20000
    });
    const creator = profileResp.data || {};
    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, {
      accessToken,
      creator,
      ts: Date.now()
    });
    setSessionCookie(res, sid);
    return res.redirect("/");
  } catch (err) {
    console.error(
      "OAuth callback failed:",
      err?.response?.status,
      err?.response?.data || err.message
    );
    return res
      .status(500)
      .send("Authentication failed. Check Render logs.");
  }
});
// =========================
// DANIAPP OAUTH START
// =========================
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res
      .status(503)
      .send("Missing DANI_CLIENT_ID / DANI_CLIENT_SECRET / DANI_REDIRECT_URI in environment.");
  }
  const pkce = createPkceState();
  const redirectUri = DANI_REDIRECT_URI;
  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set(
    "scope",
    [
      "openid",
      "offline_access",
      "write:post",
      "write:media",
      "write:chat",
      "read:creator",
      "read:fan",
      "read:chat",
      "read:media",
      "read:post",
      "read:self"
    ].join(" ")
  );
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  console.log("DANI AUTH URL:", authUrl.toString());
  return res.redirect(authUrl.toString());
});
// =========================
// DANIAPP OAUTH CALLBACK
// =========================
app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;
  if (error) {
    return res
      .status(400)
      .send(`Fanvue denied authorization: ${error} ${error_description || ""}`);
  }
  if (!code || !state) {
    return res.status(400).send("Missing code/state");
  }
  const st = oauthStates.get(state);
  if (!st) {
    return res.status(400).send("Invalid/expired state. Restart connection.");
  }
  oauthStates.delete(state);
  try {
    const redirectUri = DANI_REDIRECT_URI;
    const basicAuth = Buffer
      .from(`${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`)
      .toString("base64");
    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri,
        code_verifier: st.codeVerifier
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`
        },
        timeout: 20000
      }
    );
    const accessToken = tokenResp.data.access_token;
    if (!accessToken) {
      throw new Error("No access_token returned");
    }
    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    };
    let creator = {
      app: "On My Time",
      connected: true
    };
    try {
      const profileResp = await axios.get("https://api.fanvue.com/users/me", {
        headers: apiHeaders,
        timeout: 20000
      });
      creator = {
        ...creator,
        ...(profileResp.data || {})
      };
    } catch (profileErr) {
      console.error(
        "DANI PROFILE FETCH FAILED:",
        profileErr?.response?.status,
        profileErr?.response?.data || profileErr.message
      );
    }
    const profile = extractCreatorProfile(creator);
    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, {
      accessToken,
      creator,
      ts: Date.now()
    });
    setSessionCookie(res, sid);
    console.log("DANIAPP TOKEN SUCCESS");
    console.log("SESSION CREATED:", sid);
    return res.redirect(
      "https://thesuccessmindset.club/daniapp/index.html" +
        "?connected=1" +
        "&name=" + encodeURIComponent(profile.name) +
        "&handle=" + encodeURIComponent(profile.handle) +
        "&avatar=" + encodeURIComponent(profile.avatar)
    );
  } catch (err) {
    console.error(
      "DANIAPP OAUTH FAILED:",
      err?.response?.status,
      err?.response?.data || err.message
    );
    return res
      .status(500)
      .send("DaniApp OAuth failed. Check Render logs.");
  }
});
// =========================
// DANIAPP SINGLE POST API
// =========================
app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  const s = getSession(req);
  console.log("SIGNED COOKIES:", JSON.stringify(req.signedCookies));
  console.log("RAW COOKIE:", req.headers.cookie);
  console.log("SESSION FOUND:", !!s);
  console.log("ALL SESSION IDS:", JSON.stringify(Array.from(sessions.keys())));
  if (!s || !s.accessToken) {
    console.log("AUTH FAILURE: SESSION NOT FOUND");
    return res.status(401).json({
      ok: false,
      error: "Fanvue is not connected. Reconnect Fanvue first."
    });
  }
  if (!req.file) {
    console.log("UPLOAD FAILURE: NO FILE");
    return res.status(400).json({
      ok: false,
      error: "No media file uploaded."
    });
  }
  try {
    console.log("STARTING SINGLE POST FLOW");
    const result = await uploadMediaAndCreatePost({
      accessToken: s.accessToken,
      file: req.file,
      caption: String(req.body.caption || "").trim(),
      audience: normalizeAudience(req.body.audience),
      price: req.body.price,
      postNow: req.body.postNow === "true",
      scheduleTime: req.body.scheduleTime
    });
    console.log("POST SUCCESS:", JSON.stringify(result));
    return res.json({
      ok: true,
      result
    });
  } catch (err) {
    console.error(
      "DANI POST FAILED:",
      err?.response?.status,
      JSON.stringify(err?.response?.data),
      err.message
    );
    return res.status(500).json({
      ok: false,
      error: err?.response?.data || err.message
    });
  }
});
// =========================
// DANIAPP BULK POST API
// =========================
app.post("/daniapp/api/bulk-post", upload.single("bulkFile"), async (req, res) => {
  const s = getSession(req);
  if (!s || !s.accessToken) {
    return res.status(401).json({
      ok: false,
      error: "Fanvue is not connected. Reconnect Fanvue first."
    });
  }
  if (!req.file) {
    return res.status(400).json({
      ok: false,
      error: "No CSV/XLS file uploaded."
    });
  }
  let rows;
  try {
    rows = parseBulkFile(req.file);
  } catch (err) {
    return res.status(400).json({
      ok: false,
      error: err.message
    });
  }
  if (!rows.length) {
    return res.status(400).json({
      ok: false,
      error: "Bulk file is empty."
    });
  }
  if (rows.length > 50) {
    return res.status(400).json({
      ok: false,
      error: "Bulk upload limit is 50 rows."
    });
  }
  const results = [];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const caption = String(row.caption || "").trim();
    const mediaUrl = String(row.media_url || row.mediaUrl || "").trim();
    const mediaFilename = String(row.media_filename || row.mediaFilename || "").trim();
    const audience = normalizeAudience(row.audience);
    const price = row.price || 0;
    const postNow = parseBool(row.post_now || row.postNow);
    const scheduleTime = String(row.schedule_time || row.scheduleTime || "").trim();
    if (!caption || !mediaUrl) {
      results.push({
        row: i + 1,
        ok: false,
        error: "caption and media_url are required."
      });
      continue;
    }
    if (!postNow && !scheduleTime) {
      results.push({
        row: i + 1,
        ok: false,
        error: "schedule_time is required when post_now is false."
      });
      continue;
    }
    try {
      const file = await downloadMediaFromUrl(mediaUrl, mediaFilename);
      const result = await uploadMediaAndCreatePost({
        accessToken: s.accessToken,
        file,
        caption,
        audience,
        price,
        postNow,
        scheduleTime
      });
      results.push({
        row: i + 1,
        ok: true,
        caption,
        mediaUuid: result.mediaUuid,
        postUuid: result.post?.uuid || null,
        message: postNow ? "Posted." : "Scheduled."
      });
    } catch (err) {
      const debug = {
        status: err?.response?.status || null,
        responseData: err?.response?.data || null,
        message: err.message || String(err),
        mediaUrl,
        mediaFilename,
        audience,
        price,
        postNow,
        scheduleTime
      };
      console.error(
        "BULK ROW FAILED:",
        JSON.stringify(
          {
            row: i + 1,
            caption,
            debug
          },
          null,
          2
        )
      );
      results.push({
        row: i + 1,
        ok: false,
        caption,
        media_url: mediaUrl,
        media_filename: mediaFilename,
        error: debug
      });
    }
  }
  const successCount = results.filter((r) => r.ok).length;
  const failCount = results.length - successCount;
  return res.json({
    ok: failCount === 0,
    total: results.length,
    successCount,
    failCount,
    results
  });
});
// =========================
// API ROUTES
// =========================
app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) {
    return res.status(401).json({
      error: "Not authenticated"
    });
  }
  const c = s.creator || {};
  const profile = extractCreatorProfile(c);
  return res.json({
    username: profile.name,
    handle: profile.handle,
    avatar_url: profile.avatar,
    raw: c
  });
});
app.post("/api/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) {
    sessions.delete(sid);
  }
  clearSessionCookie(res);
  return res.json({
    ok: true
  });
});
// =========================
// WEBHOOKS
// =========================
app.get("/webhooks/fanvue", (req, res) => {
  res.status(200).send("ok");
});
app.post("/webhooks/fanvue", (req, res) => {
  const ver = verifyFanvueSignature(req);
  if (!ver.ok) {
    console.warn("Webhook rejected:", ver.reason);
    return res.status(401).send("invalid signature");
  }
  const receivedAt = new Date().toISOString();
  const ip =
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "";
  const normalized = normalizeWebhook(req.body);
  const evt = {
    receivedAt,
    ip,
    headers: {
      "user-agent": req.headers["user-agent"],
      "content-type": req.headers["content-type"],
      "x-fanvue-signature": req.headers["x-fanvue-signature"],
      "x-fanvue-timestamp": req.headers["x-fanvue-timestamp"]
    },
    normalized,
    body: req.body
  };
  addEvent(evt);
  console.log("Fanvue webhook received:", {
    type: normalized.type,
    messageUuid: normalized.messageUuid,
    sender: normalized.senderHandle || normalized.senderName
  });
  return res.status(200).send("ok");
});
app.get("/api/events", (req, res) => {
  const s = getSession(req);
  if (!s) {
    return res.status(401).json({
      error: "Not authenticated"
    });
  }
  return res.json({
    count: webhookEvents.length,
    events: webhookEvents
  });
});
app.get("/api/events/last", (req, res) => {
  const s = getSession(req);
  if (!s) {
    return res.status(401).json({
      error: "Not authenticated"
    });
  }
  return res.json(webhookEvents[0] || null);
});
app.post("/api/events/clear", requireAdmin, (req, res) => {
  webhookEvents.length = 0;
  return res.json({
    ok: true
  });
});
// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("=".repeat(60));
  console.log("Dashboard:  https://fanvue-proxy2.onrender.com/");
  console.log("OAuth Start: https://fanvue-proxy2.onrender.com/oauth/start");
  console.log("Callback:    https://fanvue-proxy2.onrender.com/oauth/callback");
  console.log("Dani Start:  https://fanvue-proxy2.onrender.com/daniapp/oauth/start");
  console.log("Dani Callback: https://fanvue-proxy2.onrender.com/daniapp/oauth/callback");
  console.log("Dani Post API: https://fanvue-proxy2.onrender.com/daniapp/api/post");
  console.log("Dani Bulk API: https://fanvue-proxy2.onrender.com/daniapp/api/bulk-post");
  console.log("Webhook:     https://fanvue-proxy2.onrender.com/webhooks/fanvue");
  console.log("Events:      https://fanvue-proxy2.onrender.com/api/events");
  console.log("Last Event:  https://fanvue-proxy2.onrender.com/api/events/last");
  console.log("=".repeat(60));
});
