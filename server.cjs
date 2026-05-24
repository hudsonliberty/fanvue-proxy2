async function uploadMediaAndCreatePost({ accessToken, file, caption, audience, price, postNow, scheduleTime }) {
  try {
    console.log("📤 Starting upload with media/uploads endpoint");

    // === 1. CREATE UPLOAD SESSION - THIS IS THE KEY FIX ===
    const startRes = await axios.post("https://api.fanvue.com/media/uploads", {
      name: file.originalname,
      filename: file.originalname,
      mediaType: file.mimetype.startsWith("video/") ? "video" : "image"
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      },
      validateStatus: () => true
    });

    if (startRes.status !== 200 && startRes.status !== 201) {
      console.error("❌ Upload session failed:", startRes.status, startRes.data);
      throw new Error(`Upload session failed: ${startRes.status} - ${JSON.stringify(startRes.data)}`);
    }

    console.log("✅ Upload session created");

    const uploadId = startRes.data.uploadId || startRes.data.id;
    const mediaUuid = startRes.data.mediaUuid || startRes.data.uuid || startRes.data.id;

    if (!uploadId || !mediaUuid) {
      throw new Error("Missing uploadId or mediaUuid");
    }

    // === 2. GET SIGNED URL ===
    const signedRes = await axios.get(`https://api.fanvue.com/media/uploads/${uploadId}/parts/1/url`, {
      headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION },
      validateStatus: () => true
    });

    const signedUrl = signedRes.data?.url || signedRes.data?.signedUrl;
    if (!signedUrl) throw new Error("No signed URL received");

    // === 3. UPLOAD FILE TO S3 ===
    const putRes = await axios.put(signedUrl, file.buffer, {
      headers: { "Content-Type": file.mimetype },
      timeout: 120000
    });

    const etag = putRes.headers.etag || putRes.headers.ETag;

    // === 4. COMPLETE UPLOAD ===
    await axios.patch(`https://api.fanvue.com/media/uploads/${uploadId}`, {
      parts: [{ partNumber: 1, etag }]
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      }
    });

    console.log("✅ Media uploaded successfully");

    // === 5. CREATE POST ===
    const postPayload = {
      audience: audience || "followers-and-subscribers",
      text: caption || "",
      mediaUuids: [mediaUuid]
    };

    if (price && Number(price) > 0) postPayload.price = Number(price);

    const postRes = await axios.post("https://api.fanvue.com/posts", postPayload, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      }
    });

    return { success: true, mediaUuid, post: postRes.data };

  } catch (err) {
    console.error("❌ Upload/Post Error:", err?.response?.data || err.message);
    throw err;
  }
}
