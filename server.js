import express from "express";
import crypto from "crypto";

const app = express();

// Keep raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const VERIFY_TOKEN = process.env.IG_VERIFY_TOKEN || "dev_verify_token_change_me";
const APP_SECRET   = process.env.META_APP_SECRET   || "dev_app_secret_change_me";
const ACCESS_TOKEN = process.env.IG_ACCESS_TOKEN   || "";
const IG_USER_ID   = process.env.IG_USER_ID        || "";

let latest = { media_url: null, permalink: null, caption: null, timestamp: null };
const sseClients = new Set();

// Health check
app.get("/", (req, res) => res.type("text").send("OK"));

// Webhook verification (GET)
app.get("/ig/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});

// Webhook receiver (POST)
app.post("/ig/webhook", async (req, res) => {
  // In local dev you won't have Meta signature headers; allow bypass if APP_SECRET is placeholder
  if (APP_SECRET && !APP_SECRET.startsWith("dev_")) {
    if (!verifyMetaSignature(req)) return res.sendStatus(403);
  }

  res.sendStatus(200);

  // If we have tokens configured, fetch latest mentioned media
  if (!ACCESS_TOKEN || !IG_USER_ID) return;

  try {
    const updated = await fetchLatestMentionedMedia();
    if (updated) {
      latest = updated;
      broadcastSSE({ type: "latest", latest });
    }
  } catch (e) {
    console.error("Webhook fetch error:", e);
  }
});

// Full-screen iPad page
app.get("/screen", (req, res) => {
  res.type("html").send(`
<!doctype html><html>
<head><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Latest Mention</title>
<style>
  html,body{margin:0;height:100%;background:#000;}
  #wrap{display:flex;height:100%;align-items:center;justify-content:center;}
  img{max-width:100vw;max-height:100vh;object-fit:contain;}
  #hint{position:fixed;bottom:12px;left:12px;color:#fff;font:14px system-ui;opacity:.7;}
</style></head>
<body>
  <div id="wrap"><img id="img" src="${latest.media_url ?? ""}"></div>
  <div id="hint">Mention @yourhandle in your caption to appear here</div>
<script>
  const img = document.getElementById("img");
  const es = new EventSource("/events");
  es.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "latest" && msg.latest?.media_url) {
      img.src = msg.latest.media_url + (msg.latest.media_url.includes("?") ? "&" : "?") + "t=" + Date.now();
    }
  };
</script>
</body></html>`);
});

// SSE stream (push updates)
app.get("/events", (req, res) => {
  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");
  res.flushHeaders?.();

  sseClients.add(res);
  res.write(`data: ${JSON.stringify({ type:"latest", latest })}\n\n`);
  req.on("close", () => sseClients.delete(res));
});

function broadcastSSE(obj){
  const payload = `data: ${JSON.stringify(obj)}\n\n`;
  for (const c of sseClients) c.write(payload);
}

// Verify Meta webhook signature
function verifyMetaSignature(req) {
  const header = req.get("X-Hub-Signature-256");
  if (!header || !header.startsWith("sha256=")) return false;
  const theirSig = header.slice("sha256=".length);
  const ourSig = crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(theirSig), Buffer.from(ourSig));
  } catch { return false; }
}

// Fetch latest mentioned media (only works once tokens are set)
async function fetchLatestMentionedMedia() {
  const url =
    `https://graph.facebook.com/v19.0/${IG_USER_ID}` +
    `?fields=mentioned_media.limit(1){id,media_type,media_url,permalink,caption,timestamp}` +
    `&access_token=${encodeURIComponent(ACCESS_TOKEN)}`;

  const r = await fetch(url);
  if (!r.ok) throw new Error(await r.text());
  const data = await r.json();
  const item = data?.mentioned_media?.data?.[0];
  if (!item?.media_url) return null;
  return {
    media_url: item.media_url,
    permalink: item.permalink ?? null,
    caption: item.caption ?? null,
    timestamp: item.timestamp ?? null
  };
}

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));

