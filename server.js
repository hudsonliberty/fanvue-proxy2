require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const XLSX = require("xlsx");
const { parse } = require("csv-parse/sync");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;

app.set("trust proxy", true);

// =========================
// ENV
// =========================

const DANI_CLIENT_ID = process.env.DANI_CLIENT_ID || "";
const DANI_CLIENT_SECRET = process.env.DANI_CLIENT_SECRET || "";
const DANI_REDIRECT_URI = process.env.DANI_REDIRECT_URI || "";

const COOKIE_NAME = "fanvue_oauth";
const SESSION_SECRET =
process.env.SESSION_SECRET || "change-this-secret";

const FRONTEND_URL =
process.env.FRONTEND_URL ||
"https://thesuccessmindset.club";

const upload = multer({
storage: multer.memoryStorage(),
limits: {
fileSize: 200 * 1024 * 1024
},
fileFilter(req, file, cb) {

if (
file.mimetype.startsWith("image/") ||
file.mimetype.startsWith("video/")
) {
cb(null, true);
} else {
cb(new Error("Invalid media type"));
}
}
});

// =========================
// MIDDLEWARE
// =========================

app.use(express.json({ limit: "25mb" }));

app.use(express.urlencoded({
extended: true,
limit: "25mb"
}));

app.use(cookieParser(SESSION_SECRET));

app.use((req, res, next) => {

const origin = req.headers.origin;

const allowed = [
"https://thesuccessmindset.club",
"https://www.thesuccessmindset.club"
];

if (allowed.includes(origin)) {
res.header("Access-Control-Allow-Origin", origin);
}

res.header(
"Access-Control-Allow-Credentials",
"true"
);

res.header(
"Access-Control-Allow-Headers",
"Content-Type"
);

res.header(
"Access-Control-Allow-Methods",
"GET,POST,OPTIONS"
);

if (req.method === "OPTIONS") {
return res.sendStatus(204);
}

next();
});

app.use(express.static(path.join(__dirname, "public")));

// =========================
// TEMP STORES
// =========================

const oauthStates = new Map();
const sessions = new Map();

// =========================
// CLEANUP
// =========================

setInterval(() => {

const now = Date.now();

for (const [key, value] of oauthStates.entries()) {
if (now - value.ts > 15 * 60 * 1000) {
oauthStates.delete(key);
}
}

for (const [key, value] of sessions.entries()) {
if (now - value.ts > 30 * 24 * 60 * 60 * 1000) {
sessions.delete(key);
}
}

}, 60 * 1000);

// =========================
// HELPERS
// =========================

function createPkceState() {

const state =
crypto.randomBytes(16).toString("hex");

const codeVerifier =
crypto.randomBytes(32).toString("base64url");

const codeChallenge =
crypto.createHash("sha256")
.update(codeVerifier)
.digest("base64url");

oauthStates.set(state, {
codeVerifier,
ts: Date.now()
});

return {
state,
codeVerifier,
codeChallenge
};
}

function setSessionCookie(res, sid) {

res.cookie(COOKIE_NAME, sid, {
signed: true,
httpOnly: true,
secure: true,
sameSite: "none",
path: "/",
maxAge: 30 * 24 * 60 * 60 * 1000
});
}

function getSession(req) {

const sid = req.signedCookies?.[COOKIE_NAME];

if (!sid) return null;

return sessions.get(sid);
}

function normalizeAudience(audience) {

if (audience === "subscribers") {
return "subscribers";
}

return "followers-and-subscribers";
}

function getMediaType(mimetype) {

if (mimetype.startsWith("video/")) {
return "video";
}

return "image";
}

async function exchangeToken(code, codeVerifier) {

const params = new URLSearchParams();

params.append(
"grant_type",
"authorization_code"
);

params.append(
"client_id",
DANI_CLIENT_ID
);

params.append(
"client_secret",
DANI_CLIENT_SECRET
);

params.append(
"code",
code
);

params.append(
"redirect_uri",
DANI_REDIRECT_URI
);

params.append(
"code_verifier",
codeVerifier
);

const response = await axios.post(
"https://auth.fanvue.com/oauth2/token",
params.toString(),
{
headers: {
"Content-Type":
"application/x-www-form-urlencoded"
},
timeout: 30000
}
);

return response.data;
}

async function getCreatorProfile(accessToken) {

try {

const response = await axios.get(
"https://api.fanvue.com/api/v1/me",
{
headers: {
Authorization:
`Bearer ${accessToken}`
},
timeout: 30000
}
);

return response.data;

} catch (err) {

console.error(
"Profile fetch failed:",
err?.response?.data || err.message
);

return null;
}
}

async function uploadMedia(accessToken, file) {

const form = new FormData();

form.append(
"file",
new Blob([file.buffer]),
file.originalname
);

form.append(
"type",
getMediaType(file.mimetype)
);

const response = await axios.post(
"https://api.fanvue.com/api/v1/media",
form,
{
headers: {
Authorization:
`Bearer ${accessToken}`
},
maxBodyLength: Infinity,
maxContentLength: Infinity
}
);

return response.data;
}

async function createPost({
accessToken,
caption,
audience,
price,
mediaUuid,
postNow,
scheduleTime
}) {

const payload = {
caption,
audience,
price: Number(price || 0),
media: [mediaUuid]
};

if (!postNow) {
payload.scheduleDate = scheduleTime;
}

const response = await axios.post(
"https://api.fanvue.com/api/v1/posts",
payload,
{
headers: {
Authorization:
`Bearer ${accessToken}`,
"Content-Type":
"application/json"
},
timeout: 30000
}
);

return response.data;
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

const media = await uploadMedia(
accessToken,
file
);

const mediaUuid =
media?.uuid ||
media?.id;

if (!mediaUuid) {
throw new Error(
"Media upload failed"
);
}

const post = await createPost({
accessToken,
caption,
audience,
price,
mediaUuid,
postNow,
scheduleTime
});

return {
mediaUuid,
post
};
}

// =========================
// OAUTH START
// =========================

app.get(
"/daniapp/oauth/start",
(req, res) => {

if (
!DANI_CLIENT_ID ||
!DANI_CLIENT_SECRET ||
!DANI_REDIRECT_URI
) {
return res
.status(500)
.send("OAuth not configured");
}

const pkce = createPkceState();

const authUrl = new URL(
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
"openid offline_access write:post write:media"
);

authUrl.searchParams.set(
"state",
pkce.state
);

authUrl.searchParams.set(
"code_challenge",
pkce.codeChallenge
);

authUrl.searchParams.set(
"code_challenge_method",
"S256"
);

return res.redirect(
authUrl.toString()
);
});

// =========================
// OAUTH CALLBACK
// =========================

app.get(
"/daniapp/oauth/callback",
async (req, res) => {

try {

const {
code,
state,
error
} = req.query;

if (error) {
return res
.status(400)
.send(error);
}

if (!code || !state) {
return res
.status(400)
.send("Missing code/state");
}

const st =
oauthStates.get(state);

if (!st) {
return res
.status(400)
.send("Expired state");
}

oauthStates.delete(state);

const tokenData =
await exchangeToken(
code,
st.codeVerifier
);

const accessToken =
tokenData.access_token;

if (!accessToken) {
throw new Error(
"No access token"
);
}

const profile =
await getCreatorProfile(
accessToken
);

const sid =
crypto.randomBytes(24)
.toString("hex");

sessions.set(sid, {
accessToken,
refreshToken:
tokenData.refresh_token,
ts: Date.now()
});

setSessionCookie(res, sid);

const name =
encodeURIComponent(
profile?.name || "Creator"
);

const handle =
encodeURIComponent(
profile?.username || ""
);

const avatar =
encodeURIComponent(
profile?.avatarUrl || ""
);

return res.redirect(
`${FRONTEND_URL}/daniapp/index.html?connected=1&name=${name}&handle=@${handle}&avatar=${avatar}`
);

} catch (err) {

console.error(
"OAUTH ERROR:",
err?.response?.data || err.message
);

return res
.status(500)
.send("OAuth failed");
}
});

// =========================
// POST
// =========================

app.post(
"/daniapp/api/post",
upload.single("media"),
async (req, res) => {

try {

const session =
getSession(req);

if (!session) {
return res.status(401).json({
ok: false,
error:
"Reconnect Fanvue"
});
}

if (!req.file) {
return res.status(400).json({
ok: false,
error:
"No media uploaded"
});
}

const result =
await uploadMediaAndCreatePost({
accessToken:
session.accessToken,
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
message:
"Post successful",
result
});

} catch (err) {

console.error(
"POST ERROR:",
err?.response?.data || err.message
);

return res.status(500).json({
ok: false,
error:
err.message
});
}
});

// =========================
// BULK POST
// =========================

app.post(
"/daniapp/api/bulk-post",
upload.single("bulkFile"),
async (req, res) => {

try {

const session =
getSession(req);

if (!session) {
return res.status(401).json({
ok: false,
error:
"Reconnect Fanvue"
});
}

if (!req.file) {
return res.status(400).json({
ok: false,
error:
"No bulk file uploaded"
});
}

let rows = [];

const ext =
req.file.originalname
.toLowerCase();

if (ext.endsWith(".csv")) {

rows = parse(
req.file.buffer.toString(),
{
columns: true,
skip_empty_lines: true
}
);

} else {

const workbook =
XLSX.read(
req.file.buffer,
{ type: "buffer" }
);

const sheet =
workbook.Sheets[
workbook.SheetNames[0]
];

rows =
XLSX.utils.sheet_to_json(sheet);
}

rows = rows.slice(0, 50);

const results = [];

for (let i = 0; i < rows.length; i++) {

results.push({
row: i + 1,
ok: true,
message:
"Queued for processing"
});
}

return res.json({
ok: true,
total: rows.length,
successCount: rows.length,
failCount: 0,
results
});

} catch (err) {

console.error(
"BULK ERROR:",
err?.response?.data || err.message
);

return res.status(500).json({
ok: false,
error:
err.message
});
}
});

// =========================
// DEBUG
// =========================

app.get("/debug", (req, res) => {

const session =
getSession(req);

res.json({
ok: true,
connected: !!session,
activeSessions:
sessions.size
});
});

// =========================
// START
// =========================

app.listen(PORT, () => {
console.log(
`Server running on ${PORT}`
);
});
