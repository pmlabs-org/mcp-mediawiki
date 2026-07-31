const http = require("http");
const { randomUUID, createHash } = require("crypto");
const { URL } = require("url");

const fs = require("fs");

const PORT = parseInt(process.env.PORT || "8080", 10);
const BACKEND_PORT = parseInt(process.env.BACKEND_PORT || "8081", 10);
const AUTH_TOKEN = (process.env.MCP_AUTH_TOKEN || "").trim();
const OAUTH_CLIENT_ID = (process.env.OAUTH_CLIENT_ID || "claude-pathfinder").trim();
const OAUTH_CLIENT_SECRET = (process.env.OAUTH_CLIENT_SECRET || "").trim();
const TOKEN_TTL_SECONDS = 7776000;
const TOKEN_META_PATH = "/tmp/mcp-token-meta.json";

let tokenIssuedAt = null;
try {
  const meta = JSON.parse(fs.readFileSync(TOKEN_META_PATH, "utf8"));
  if (meta.issued_at) tokenIssuedAt = meta.issued_at;
} catch { /* no prior issuance */ }

function recordTokenIssuance() {
  tokenIssuedAt = Math.floor(Date.now() / 1000);
  try {
    fs.writeFileSync(TOKEN_META_PATH, JSON.stringify({ issued_at: tokenIssuedAt, expires_in: TOKEN_TTL_SECONDS }));
  } catch (err) {
    console.error("Failed to write token meta:", err.message);
  }
}

const authCodes = {};

function parseBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString();
      const ct = req.headers["content-type"] || "";
      if (ct.includes("application/json")) {
        try { resolve(JSON.parse(raw)); } catch { resolve(raw); }
      } else if (ct.includes("urlencoded")) {
        resolve(Object.fromEntries(new URLSearchParams(raw)));
      } else { resolve(raw); }
    });
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

// Transparent byte-pipe to the internal MCP server. No session state held
// in this layer. If the backend returns 404 for an unknown session id we
// propagate it as-is so the client can reinitialize cleanly per MCP spec.
// Do NOT silently remap stale ids to new sessions — see
// PM-Labs/mcp-playwright@1d75780 for root cause analysis.
function proxy(req, res, bodyBuf) {
  // Strip the public-facing Authorization (Bearer is consumed by this proxy,
  // not the upstream MCP) and force the host header to localhost so upstream
  // host checks accept the proxied request.
  const headers = { ...req.headers, host: "localhost:" + BACKEND_PORT };
  delete headers["authorization"];
  delete headers["content-length"];
  if (bodyBuf) headers["content-length"] = bodyBuf.length;
  const proxyReq = http.request(
    { hostname: "127.0.0.1", port: BACKEND_PORT, path: req.url, method: req.method, headers },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on("error", (e) => { console.error("[PROXY] Backend error:", e.message); sendJson(res, 502, { error: "backend_unavailable" }); });
  if (bodyBuf) proxyReq.write(bodyBuf);
  proxyReq.end();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost:" + PORT);
  const path = url.pathname;

  if (path === "/health") return sendJson(res, 200, { status: "ok" });

  if (path === "/.well-known/oauth-protected-resource") {
    const base = "https://" + req.headers.host;
    return sendJson(res, 200, { resource: base + "/mcp", authorization_servers: [base] });
  }

  if (path === "/.well-known/oauth-authorization-server") {
    const base = "https://" + req.headers.host;
    return sendJson(res, 200, {
      issuer: base,
      authorization_endpoint: base + "/authorize",
      token_endpoint: base + "/oauth/token",
      grant_types_supported: ["authorization_code", "client_credentials"],
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
    });
  }

  if (path === "/.well-known/token-expiry" && req.method === "GET") {
    if (tokenIssuedAt === null) return sendJson(res, 404, { error: "no_token_issued" });
    return sendJson(res, 200, { issued_at: tokenIssuedAt, expires_in: TOKEN_TTL_SECONDS, expires_at: tokenIssuedAt + TOKEN_TTL_SECONDS });
  }

  if (path === "/authorize" && req.method === "GET") {
    const p = url.searchParams;
    if (p.get("client_id") !== OAUTH_CLIENT_ID) return sendJson(res, 401, { error: "invalid_client" });
    if (p.get("response_type") !== "code") return sendJson(res, 400, { error: "unsupported_response_type" });
    if (!p.get("code_challenge")) return sendJson(res, 400, { error: "code_challenge required" });
    const code = randomUUID();
    authCodes[code] = {
      codeChallenge: p.get("code_challenge"),
      codeChallengeMethod: p.get("code_challenge_method") || "S256",
      redirectUri: p.get("redirect_uri"),
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    const redir = new URL(p.get("redirect_uri"));
    redir.searchParams.set("code", code);
    if (p.get("state")) redir.searchParams.set("state", p.get("state"));
    res.writeHead(302, { Location: redir.toString() });
    return res.end();
  }

  if (path === "/oauth/token" && req.method === "POST") {
    const body = await parseBody(req);
    if (body.grant_type === "authorization_code") {
      const stored = authCodes[body.code];
      if (!stored || stored.expiresAt < Date.now()) return sendJson(res, 400, { error: "invalid_grant" });
      delete authCodes[body.code];
      const verifier = body.code_verifier;
      if (verifier) {
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        if (challenge !== stored.codeChallenge) return sendJson(res, 400, { error: "invalid_grant" });
      }
      recordTokenIssuance();
      return sendJson(res, 200, { access_token: AUTH_TOKEN, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
    }
    let cid, csec;
    const ba = req.headers["authorization"];
    if (ba && ba.startsWith("Basic ")) {
      const decoded = Buffer.from(ba.slice(6), "base64").toString();
      const colon = decoded.indexOf(":");
      cid = decoded.slice(0, colon); csec = decoded.slice(colon + 1);
    } else { cid = body.client_id; csec = body.client_secret; }
    if (cid !== OAUTH_CLIENT_ID || csec !== OAUTH_CLIENT_SECRET) return sendJson(res, 401, { error: "invalid_client" });
    recordTokenIssuance();
    return sendJson(res, 200, { access_token: AUTH_TOKEN, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
  }

  if (path === "/mcp" || path.startsWith("/mcp/")) {
    if (AUTH_TOKEN) {
      const ah = req.headers["authorization"];
      if (!ah || !ah.startsWith("Bearer ")) {
        res.writeHead(401, {
          "WWW-Authenticate": "Bearer resource_metadata=\"https://" + req.headers.host + "/.well-known/oauth-protected-resource\"",
          "Content-Type": "application/json",
        });
        return res.end(JSON.stringify({ error: "Unauthorized" }));
      }
      if (ah.slice(7) !== AUTH_TOKEN) {
        res.writeHead(401, { "WWW-Authenticate": "Bearer error=\"invalid_token\"", "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Unauthorized" }));
      }
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => proxy(req, res, Buffer.concat(chunks)));
    return;
  }

  sendJson(res, 404, { error: "not_found" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("MediaWiki OAuth proxy listening on :" + PORT + ", backend on :" + BACKEND_PORT);
});
