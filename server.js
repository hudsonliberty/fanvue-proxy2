// server.cjs — On My Time / DaniApp Fanvue OAuth + Single + Bulk Posting

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

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();
const FANVUE_API_VERSION = "2025-06-26";

const oauthStates = new Map();
const sessions = new Map();

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

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
  res.clearCookie(COOKIE_NAME, { path: "/" });
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

  oauthStates.set(state, { nonce, codeVerifier, ts: Date.now() });

  return { state, nonce, codeVerifier, codeChallenge };
}

function getMediaType(mimetypeOrFilename) {
  const v = String(mimetypeOrFilename || "").toLowerCase();

  if (v.startsWith("video/") || /\.(mp4|mov|webm|m4v)$/i.test(v)) return "video";
  if (v.startsWith("audio/") || /\.(mp3|wav|m4a)$/i.test(v)) return "audio";
  if (v.startsWith("image/") || /\.(jpg|jpeg|png|webp|gif)$/i.test(v)) return "image";

  return "document";
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
    const keys = [
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

    for (const key of keys) {
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

  if (v === "followers-and-subscribers") return v;
  if (v === "subscribers") return v;

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

  const signedUrl = findSignedUrl(signedUrlResp.data);

  if (!signedUrl) {
    console.log("SIGNED URL RESPONSE:", JSON.stringify(signedUrlResp.data));
    throw new Error("Fanvue did not return a signed upload URL.");
  }

  const uploadPartResp = await axios.put(signedUrl, file.buffer, {
    headers: {
      "Content-Type": file.mimetype || "application/octet-stream"
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    timeout: 120000,
    validateStatus: (status) => status >= 200 && status < 300
  });

  const etagRaw =
    uploadPartResp.headers.etag ||
    uploadPartResp.headers.ETag ||
    "";

  const etag = String(etagRaw).replace(/^"|"$/g, "");

  const completePayload = etag
    ? { parts: [{ ETag: etag, PartNumber: 1 }] }
    : { parts: [{ PartNumber: 1 }] };

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

  await new Promise((resolve) => setTimeout(resolve, 8000));

  const postPayload = {
    text: caption,
    mediaUuids: [mediaUuid],
    audience,
    visibility: "followers-and-subscribers",
    isArchived: false
  };

  const priceNumber = Number(price || 0);

  if (priceNumber > 0) {
    postPayload.price = Math.round(priceNumber * 100);
  }

  if (!postNow && scheduleTime) {
    postPayload.publishAt = new Date(scheduleTime).toISOString();
  }

  const postResp = await axios.post(
    "https://api.fanvue.com/posts",
    postPayload,
    {
      headers: {
        ...fanvueHeaders,
        "Content-Type": "application/json"
      },
      timeout: 30000,
      validateStatus: (status) => status >= 200 && status < 300
    }
  );

  return {
    mediaUuid,
    uploadId,
    mediaStatus: completeResp.data,
    post: postResp.data
  };
}

console.log("=".repeat(60));
console.log("ON MY TIME FANVUE SERVICE STARTING");
console.log("DANI_CLIENT_ID present:", !!DANI_CLIENT_ID);
console.log("DANI_CLIENT_SECRET present:", !!DANI_CLIENT_SECRET);
console.log("DANI_REDIRECT_URI present:", !!DANI_REDIRECT_URI);
console.log("PORT:", PORT);
console.log("=".repeat(60));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res
      .status(503)
      .send("Missing DANI_CLIENT_ID / DANI_CLIENT_SECRET / DANI_REDIRECT_URI.");
  }

  const pkce = createPkceState();

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set(
    "scope",
    "openid offline_access write:post write:media read:self"
  );
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res
      .status(400)
      .send(`Fanvue denied authorization: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state.");

  oauthStates.delete(state);

  try {
    const basicAuth = Buffer.from(
      `${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`
    ).toString("base64");

    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: DANI_REDIRECT_URI,
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
    if (!accessToken) throw new Error("No access_token returned");

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
        "DANIAPP PROFILE FETCH FAILED:",
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

    return res.status(500).send("DaniApp OAuth failed. Check Render logs.");
  }
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
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
      error: "No media file uploaded."
    });
  }

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

    return res.json({
      ok: true,
      message: req.body.postNow === "true" ? "Post created." : "Post scheduled.",
      ...result
    });
  } catch (err) {
    console.error(
      "DANIAPP POST FAILED:",
      err?.response?.status,
      err?.response?.data || err.message
    );

    return res.status(500).json({
      ok: false,
      error: "Fanvue post failed.",
      details: err?.response?.data || err.message
    });
  }
});

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
      results.push({
        row: i + 1,
        ok: false,
        caption,
        error: err?.response?.data || err.message
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

app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  const profile = extractCreatorProfile(s.creator || {});

  return res.json({
    username: profile.name,
    handle: profile.handle,
    avatar_url: profile.avatar,
    raw: s.creator || {}
  });
});

app.post("/api/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("Dani Start: https://fanvue-proxy2.onrender.com/daniapp/oauth/start");
  console.log("Dani Post API: https://fanvue-proxy2.onrender.com/daniapp/api/post");
  console.log("Dani Bulk API: https://fanvue-proxy2.onrender.com/daniapp/api/bulk-post");
  console.log("=".repeat(60));
});
