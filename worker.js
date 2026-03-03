const DAILY_LIMIT = 3;
const ALLOWED_ORIGINS = [
    "https://slvtrs.github.io",
    "https://vibecadaver.slvtrs.com",
];
let ENFORCE_ALLOWED_ORIGINS = true; 
 // ENFORCE_ALLOWED_ORIGINS = false; // uncomment to enable local dev

function corsHeaders(requestOrigin) {
    const origin = !ENFORCE_ALLOWED_ORIGINS ? "*"
        : ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0];
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Api-Key, X-Retry",
        "Access-Control-Expose-Headers": "X-Remaining-Today",
    };
}

export default {
    async fetch(request, env) {
        const origin = request.headers.get("Origin") || "";

        if (request.method === "OPTIONS") {
            return new Response(null, { status: 204, headers: corsHeaders(origin) });
        }

        // Reject any request whose Origin or Referer doesn't match the live site.
        // This stops browser-based attacks outright. Non-browser tools (curl, scripts)
        // can spoof these headers, but they still hit the server-side rate limit.
        const referer = request.headers.get("Referer") || "";
        const originOk = ALLOWED_ORIGINS.includes(origin);
        const refererOk = ALLOWED_ORIGINS.some(o => referer.startsWith(o));
        if (ENFORCE_ALLOWED_ORIGINS && !originOk && !refererOk) {
            return new Response(null, { status: 403 });
        }

        const url = new URL(request.url);

        if (request.method === "GET" && url.pathname === "/api/status") {
            const ip = request.headers.get("CF-Connecting-IP") || "unknown";
            const today = new Date().toISOString().slice(0, 10);
            const used = parseInt((await env.RATE_LIMIT_KV.get(`rl:${ip}:${today}`)) || "0");
            return new Response(JSON.stringify({ remaining: Math.max(0, DAILY_LIMIT - used) }), {
                headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
            });
        }

        if (request.method === "POST" && url.pathname === "/api/transmute") {
            return handleTransmute(request, env, origin);
        }

        if (request.method === "POST" && url.pathname === "/api/publish") {
            return handlePublish(request, env, origin);
        }

        return new Response(null, { status: 404 });
    }
};

async function handleTransmute(request, env, origin) {
    const userKey = request.headers.get("X-Api-Key");

    // If user provides their own key, proxy directly — no rate limit
    if (userKey) {
        const body = await request.text();
        const upstream = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
                "x-api-key": userKey,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            body,
        });
        const data = await upstream.text();
        return new Response(data, {
            status: upstream.status,
            headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
        });
    }

    // No user key — use shared key with rate limit
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const today = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
    const kvKey = `rl:${ip}:${today}`;

    // X-Retry: true means the client's patch failed — reuse the same rate-limit slot,
    // so retries bypass the rate limit check entirely.
    const isRetry = request.headers.get("X-Retry") === "true";

    const current = parseInt((await env.RATE_LIMIT_KV.get(kvKey)) || "0");
    if (!isRetry && current >= DAILY_LIMIT) {
        return new Response(
            JSON.stringify({ error: `You've used all ${DAILY_LIMIT} contributions for today. Come back tomorrow.` }),
            { status: 429, headers: { "Content-Type": "application/json", ...corsHeaders(origin) } }
        );
    }

    let body;
    if (isRetry) {
        const { currentCode, prompt } = await request.json();
        body = JSON.stringify({
            model: "claude-sonnet-4-6",
            max_tokens: 16000,
            system: "You are editing a webpage. Return ONLY the complete modified HTML starting with <!DOCTYPE html>. No markdown, no explanation, nothing else.",
            messages: [{ role: "user", content: `Current page:\n${currentCode}\n\nChange: ${prompt}` }]
        });
    } else {
        body = await request.text();
    }

    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
            "x-api-key": env.ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        body,
    });

    // Only increment counter on the first attempt, not retries
    if (upstream.ok && !isRetry) {
        await env.RATE_LIMIT_KV.put(kvKey, String(current + 1), { expirationTtl: 86400 });
    }

    const data = await upstream.text();
    return new Response(data, {
        status: upstream.status,
        headers: {
            "Content-Type": "application/json",
            "X-Remaining-Today": String(Math.max(0, DAILY_LIMIT - (current + 1))),
            ...corsHeaders(origin)
        },
    });
}

const REPO = "slvtrs/ouroboros";

// Exact paths the publish endpoint is allowed to touch
const ALLOWED_PATHS = [
    { pattern: `/repos/${REPO}/contents/content.html`, methods: ["GET", "PUT"] },
    { pattern: `/repos/${REPO}/commits`,               methods: ["GET"] },
];

function isAllowedGitHubPath(path, method) {
    const clean = path.split("?")[0]; // strip query string for matching
    return ALLOWED_PATHS.some(rule =>
        clean === rule.pattern && rule.methods.includes(method?.toUpperCase())
    );
}

async function handlePublish(request, env, origin) {
    const { path, method, body } = await request.json();

    if (!isAllowedGitHubPath(path, method)) {
        return new Response(
            JSON.stringify({ error: "Forbidden path." }),
            { status: 403, headers: { "Content-Type": "application/json", ...corsHeaders(origin) } }
        );
    }

    const upstream = await fetch(`https://api.github.com${path}`, {
        method: method || "GET",
        headers: {
            "Authorization": `token ${env.GITHUB_PAT}`,
            "Content-Type": "application/json",
            "User-Agent": "vibecadaver-worker",
        },
        body: body ? JSON.stringify(body) : undefined,
    });

    const data = await upstream.text();
    return new Response(data, {
        status: upstream.status,
        headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
    });
}
