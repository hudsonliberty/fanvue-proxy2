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

app.use((req, res, next) => {
  res.header(
    "Access-Control-Allow-Origin",
    "https://thesuccessmindset.club"
  );

  res.header(
    "Access-Control-Allow-Credentials",
    "true"
  );

  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,PUT,OPTIONS"
  );

  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const CLIENT_ID =
  (process.env.CLIENT_ID || "").trim();

const CLIENT_SECRET =
  (process.env.CLIENT_SECRET || "").trim();

const DANI_CLIENT_ID =
  (process.env.DANI_CLIENT_ID || "").trim();

const DANI_CLIENT_SECRET =
  (process.env.DANI_CLIENT_SECRET || "").trim();

const DANI_REDIRECT_URI =
  (process.env.DANI_REDIRECT_URI || "").trim();

const COOKIE_NAME =
  (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();

const SESSION_SECRET =
  (process.env.SESSION_SECRET || "change-me").trim();

const FANVUE_API_VERSION = "2025-06-26";

const oauthStates = new Map();
const sessions = new Map();

app.use(express.json({ limit: "25mb" }));

app.use(express.urlencoded({
  extended: true,
  limit: "25mb"
}));

app.use(cookieParser(SESSION_SECRET));

app.use(express.static(path.join(__dirname, "public")));

function baseUrl(req) {
  return `https://${req.get("host")}`;
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

function createPkceState() {
  const state =
    crypto.randomBytes(16).toString("hex");

  const nonce =
    crypto.randomBytes(16).toString("hex");

  const codeVerifier =
    crypto.randomBytes(32).toString("base64url");

  const codeChallenge =
    crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

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

function getMediaType(mimetypeOrFilename) {
  const v =
    String(mimetypeOrFilename || "").toLowerCase();

  if (
    v.startsWith("video/") ||
    /\.(mp4|mov|webm|m4v)$/i.test(v)
  ) {
    return "video";
  }

  if (
    v.startsWith("audio/") ||
    /\.(mp3|wav|m4a)$/i.test(v)
  ) {
    return "audio";
  }

  if (
    v.startsWith("image/") ||
    /\.(jpg|jpeg|png|webp|gif)$/i.test(v)
  ) {
    return "image";
  }

  return "document";
}

function findSignedUrl(value) {
  if (!value) return "";

  if (typeof value === "string") {
    return value.startsWith("https://")
      ? value
      : "";
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findSignedUrl(item);
      if (found) return found;
    }
  }

  if (typeof value === "object") {
    for (const key of Object.keys(value)) {
      const found = findSignedUrl(value[key]);
      if (found) return found;
    }
  }

  return "";
}

function parseBool(value) {
  const v =
    String(value || "")
      .trim()
      .toLowerCase();

  return (
    v === "true" ||
    v === "yes" ||
    v === "1"
  );
}

function normalizeAudience(value) {
  const v =
    String(value || "").trim();

  if (v === "subscribers") {
    return v;
  }

  return "followers-and-subscribers";
}

function parseBulkFile(file) {
  const name =
    file.originalname.toLowerCase();

  if (name.endsWith(".csv")) {
    return parse(
      file.buffer.toString("utf8"),
      {
        columns: true,
        skip_empty_lines: true,
        trim: true
      }
    );
  }

  if (
    name.endsWith(".xlsx") ||
    name.endsWith(".xls")
  ) {
    const workbook =
      XLSX.read(file.buffer, {
        type: "buffer"
      });

    const sheet =
      workbook.Sheets[
        workbook.SheetNames[0]
      ];

    return XLSX.utils.sheet_to_json(
      sheet,
      {
        defval: ""
      }
    );
  }

  throw new Error(
    "Only CSV, XLS, or XLSX supported."
  );
}

async function downloadMediaFromUrl(
  mediaUrl,
  filename
) {
  const response = await axios.get(
    mediaUrl,
    {
      responseType: "arraybuffer",
      timeout: 120000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    }
  );

  const contentType =
    response.headers["content-type"] ||
    "application/octet-stream";

  return {
    buffer: Buffer.from(response.data),
    mimetype: contentType,
    originalname:
      filename ||
      path.basename(
        new URL(mediaUrl).pathname
      ) ||
      "media-file"
  };
}

async function waitForMediaReady(
  mediaUuid,
  fanvueHeaders
) {
  const maxAttempts = 24;
  const delayMs = 5000;

  for (
    let attempt = 1;
    attempt <= maxAttempts;
    attempt++
  ) {
    const resp = await axios.get(
      `https://api.fanvue.com/media/${encodeURIComponent(mediaUuid)}`,
      {
        headers: fanvueHeaders,
        timeout: 30000,
        validateStatus: status =>
          status >= 200 &&
          status < 500
      }
    );

    console.log(
      "MEDIA STATUS:",
      JSON.stringify(resp.data)
    );

    const status =
      resp.data?.status || "";

    if (status === "ready") {
      return resp.data;
    }

    if (status === "error") {
      throw new Error(
        `Media processing failed: ${mediaUuid}`
      );
    }

    await new Promise(resolve =>
      setTimeout(resolve, delayMs)
    );
  }

  throw new Error(
    `Media did not become ready: ${mediaUuid}`
  );
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
    "X-Fanvue-API-Version":
      FANVUE_API_VERSION
  };

  const uploadSession =
    await axios.post(
      "https://api.fanvue.com/media/uploads",
      {
        name: file.originalname,
        filename: file.originalname,
        mediaType: getMediaType(
          file.mimetype ||
          file.originalname
        )
      },
      {
        headers: {
          ...fanvueHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );

  console.log(
    "UPLOAD SESSION:",
    JSON.stringify(uploadSession.data)
  );

  const mediaUuid =
    uploadSession.data.mediaUuid;

  const uploadId =
    uploadSession.data.uploadId;

  const signedUrlResp =
    await axios.get(
      `https://api.fanvue.com/media/uploads/${uploadId}/parts/1/url`,
      {
        headers: fanvueHeaders
      }
    );

  console.log(
    "SIGNED URL:",
    JSON.stringify(signedUrlResp.data)
  );

  const signedUrl =
    findSignedUrl(
      signedUrlResp.data
    );

  if (!signedUrl) {
    throw new Error(
      "No signed upload URL returned."
    );
  }

  const uploadPartResp =
    await axios.put(
      signedUrl,
      file.buffer,
      {
        headers: {
          "Content-Type":
            file.mimetype ||
            "application/octet-stream"
        },
        timeout: 120000,
        maxBodyLength: Infinity,
        maxContentLength: Infinity
      }
    );

  const etagRaw =
    uploadPartResp.headers.etag ||
    "";

  const etag =
    String(etagRaw).replace(
      /^"|"$/g,
      ""
    );

  const completeResp =
    await axios.patch(
      `https://api.fanvue.com/media/uploads/${uploadId}`,
      {
        parts: [
          {
            ETag: etag,
            PartNumber: 1
          }
        ]
      },
      {
        headers: {
          ...fanvueHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );

  console.log(
    "UPLOAD COMPLETE:",
    JSON.stringify(completeResp.data)
  );

  await waitForMediaReady(
    mediaUuid,
    fanvueHeaders
  );

  const postPayload = {
    text: caption,
    mediaUuids: [mediaUuid],
    audience
  };

  const priceNumber =
    Number(price || 0);

  if (priceNumber > 0) {
    postPayload.price =
      Math.round(priceNumber * 100);
  }

  if (!postNow && scheduleTime) {
    postPayload.publishAt =
      new Date(
        scheduleTime
      ).toISOString();
  }

  console.log(
    "POST PAYLOAD:",
    JSON.stringify(postPayload)
  );

  const postResp =
    await axios.post(
      "https://api.fanvue.com/posts",
      postPayload,
      {
        headers: {
          ...fanvueHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );

  console.log(
    "POST RESPONSE:",
    JSON.stringify(postResp.data)
  );

  return {
    mediaUuid,
    uploadId,
    post: postResp.data
  };
}

/* FRONTEND */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "dashboard.html"
    )
  );
});

/* DANI OAUTH */

app.get(
  "/daniapp/oauth/start",
  (req, res) => {

    const pkce =
      createPkceState();

    const authUrl =
      new URL(
        "https://auth.fanvue.com/oauth2/auth"
      );

    authUrl.searchParams.set(
      "response_type",
      "code"
    );

    authUrl.searchParams.set(
      "client_id",
      DANI_CLIENT_ID
    );

    authUrl.searchParams.set(
      "redirect_uri",
      DANI_REDIRECT_URI
    );

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

    authUrl.searchParams.set(
      "state",
      pkce.state
    );

    authUrl.searchParams.set(
      "nonce",
      pkce.nonce
    );

    authUrl.searchParams.set(
      "code_challenge",
      pkce.codeChallenge
    );

    authUrl.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    console.log(
      "AUTH URL:",
      authUrl.toString()
    );

    return res.redirect(
      authUrl.toString()
    );
  }
);

app.get(
  "/daniapp/oauth/callback",
  async (req, res) => {

    const {
      code,
      state
    } = req.query;

    const st =
      oauthStates.get(state);

    if (!st) {
      return res
        .status(400)
        .send("Invalid state.");
    }

    oauthStates.delete(state);

    try {

      const basicAuth =
        Buffer.from(
          `${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`
        ).toString("base64");

      const tokenResp =
        await axios.post(
          "https://auth.fanvue.com/oauth2/token",
          new URLSearchParams({
            grant_type:
              "authorization_code",
            code,
            redirect_uri:
              DANI_REDIRECT_URI,
            code_verifier:
              st.codeVerifier
          }).toString(),
          {
            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
              Authorization:
                `Basic ${basicAuth}`
            }
          }
        );

      console.log(
        "TOKEN RESPONSE:",
        JSON.stringify(tokenResp.data)
      );

      const accessToken =
        tokenResp.data.access_token;

      const sid =
        crypto
          .randomBytes(24)
          .toString("hex");

      sessions.set(sid, {
        accessToken,
        ts: Date.now()
      });

      setSessionCookie(
        res,
        sid
      );

      return res.redirect(
        "https://thesuccessmindset.club/daniapp/index.html?connected=1"
      );

    } catch (err) {

      console.error(
        "DANI OAUTH FAILED:",
        err?.response?.status,
        JSON.stringify(
          err?.response?.data
        )
      );

      return res
        .status(500)
        .send("OAuth failed.");
    }
  }
);

/* SINGLE POST */

app.post(
  "/daniapp/api/post",
  upload.single("media"),
  async (req, res) => {

    const s =
      getSession(req);

    if (!s?.accessToken) {
      return res
        .status(401)
        .json({
          ok: false,
          error:
            "Not connected."
        });
    }

    try {

      const result =
        await uploadMediaAndCreatePost({
          accessToken:
            s.accessToken,

          file: req.file,

          caption:
            String(
              req.body.caption || ""
            ).trim(),

          audience:
            normalizeAudience(
              req.body.audience
            ),

          price:
            req.body.price,

          postNow:
            req.body.postNow === "true",

          scheduleTime:
            req.body.scheduleTime
        });

      return res.json({
        ok: true,
        result
      });

    } catch (err) {

      console.error(
        "DANI POST FAILED:",
        err?.response?.status,
        JSON.stringify(
          err?.response?.data
        ),
        err.message
      );

      return res
        .status(500)
        .json({
          ok: false,
          error:
            err?.response?.data ||
            err.message
        });
    }
  }
);

app.listen(PORT, () => {
  console.log(
    `Server running on ${PORT}`
  );
});
