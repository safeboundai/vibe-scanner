// vibe-scanner dashboard server.
//
// Two endpoints do the real work:
//   GET  /api/vibe-scan?domain=…   SSE stream — spawns `python -m scans.vibe_scan_cli`
//                                  and forwards each JSON line from stdout as one SSE frame.
//   POST /api/assess               Optional GPT-4o proxy. Returns 503 when USE_AI is not
//                                  enabled or OPENAI_API_KEY is missing, so the dashboard's
//                                  client-side rules engine takes over transparently.
//
// Static dashboard lives in ./public — root path redirects to /vibe-scan.html.

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const OpenAI    = require("openai");
const path      = require("path");
const { spawn } = require("child_process");

const PORT             = parseInt(process.env.PORT || "8080", 10);
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;
const USE_AI           = process.env.USE_AI === "true";
const OPENAI_API_KEY   = process.env.OPENAI_API_KEY;
const ALLOWED_ORIGINS  = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim())
  : false; // block all cross-origin requests by default when unset

const openai = (USE_AI && OPENAI_API_KEY) ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

const app = express();

if (DASHBOARD_PASSWORD) {
  const basicAuth = require("express-basic-auth");
  app.use(basicAuth({
    users: { "admin": DASHBOARD_PASSWORD },
    challenge: true,
    realm: "VibeScan Dashboard",
  }));
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "https://cdnjs.cloudflare.com"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com"],
      "img-src": ["'self'", "data:", "https://img.shields.io"],
      "connect-src": ["'self'"],
    },
  },
}));
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
}));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, assess: openai ? "enabled" : "disabled" });
});

// GPT-4o risk-assessment proxy. The response shape mirrors Anthropic's
// {content:[{text}]} so vibe-scan.html's client-side parser works unchanged.
// When the proxy is disabled, the page falls back to its built-in rules engine.
app.post("/api/assess", async (req, res) => {
  if (!openai) {
    return res.status(503).json({ error: "Assessment engine disabled (set USE_AI=true and provide OPENAI_API_KEY)." });
  }
  const prompt = req.body?.prompt;
  if (!prompt || typeof prompt !== "string") {
    return res.status(400).json({ error: "Request body must include a non-empty 'prompt' string." });
  }
  try {
    const message = await openai.chat.completions.create({
      model: "gpt-4o",
      max_tokens: 600,
      messages: [
        {
          role: "system",
          content:
            "You are a senior security analyst at a Fortune 500 company writing risk assessments for CISOs. " +
            "Be direct, specific, and focus on business impact and regulatory exposure. " +
            "Never use bullet points. Write exactly 2 sentences.",
        },
        { role: "user", content: prompt },
      ],
    });
    const text = message.choices?.[0]?.message?.content || "";
    return res.json({ content: [{ text }] });
  } catch (err) {
    console.error("[/api/assess] OpenAI error:", err.message);
    return res.status(502).json({ error: "Assessment provider error" });
  }
});

const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

// SSE-streamed real scan. Spawns the Python CLI and forwards JSON-line events.
app.get("/api/vibe-scan", (req, res) => {
  const domain = (req.query.domain || "").toString().trim();
  if (!domain || !DOMAIN_REGEX.test(domain)) {
    return res.status(400).json({ error: "Query param 'domain' is required and must be a valid domain name." });
  }
  const name = (req.query.name || "").toString().trim();
  const maxApps = Math.max(1, Math.min(50, parseInt(req.query.max_apps, 10) || 20));

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const heartbeat = setInterval(() => res.write(": ping\n\n"), 15_000);
  const closeStream = () => { clearInterval(heartbeat); try { res.end(); } catch {} };

  // Project root is one level up — that's where scans/ lives. python3 picks up
  // a venv binary when the image is built that way; users running outside Docker
  // should activate their venv before `npm start`.
  const projectRoot = path.resolve(__dirname, "..");
  const pythonBin = process.env.PYTHON_BIN || "python3";
  const args = ["-m", "scans.vibe_scan_cli", "--domain", domain, "--max-apps", String(maxApps)];
  if (name) args.push("--name", name);

  console.log(`[vibe-scan] spawning ${pythonBin} ${args.join(" ")}`);
  const child = spawn(pythonBin, args, { cwd: projectRoot, env: process.env });

  let buf = "";
  child.stdout.on("data", chunk => {
    buf += chunk.toString();
    const lines = buf.split("\n");
    buf = lines.pop() || "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const evt = JSON.parse(trimmed);
        res.write(`data: ${JSON.stringify(evt)}\n\n`);
      } catch {
        console.warn("[vibe-scan] non-JSON line from child:", trimmed.slice(0, 200));
      }
    }
  });

  child.stderr.on("data", chunk => {
    console.warn("[vibe-scan stderr]", chunk.toString().slice(0, 500));
  });

  child.on("error", err => {
    console.error("[vibe-scan] spawn error:", err);
    res.write(`data: ${JSON.stringify({ type: "error", message: "Failed to start scanner subprocess." })}\n\n`);
    closeStream();
  });

  child.on("close", code => {
    if (code !== 0) console.warn(`[vibe-scan] child exited with code ${code}`);
    closeStream();
  });

  req.on("close", () => {
    try { child.kill("SIGTERM"); } catch {}
    closeStream();
  });
});

app.get("/", (_req, res) => res.redirect("/vibe-scan.html"));

app.listen(PORT, () => {
  console.log(`vibe-scanner listening on :${PORT} (assess=${openai ? "on" : "off"})`);
});
