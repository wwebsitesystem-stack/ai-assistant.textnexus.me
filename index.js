/**
 * Nexus Assistant Worker
 * ----------------------
 * Receives a prompt from the Nexus frontend, verifies it really came from
 * the signed-in owner (Firebase ID token, checked server-side), then lets
 * Claude decide whether to answer directly or call a tool:
 *   - github_api            -> any GitHub REST call, using GITHUB_TOKEN
 *   - composio_find_tools    -> search the Composio catalog for the right action
 *   - composio_execute_tool  -> run that action against a connected account
 *
 * Required secrets (wrangler secret put <NAME>):
 *   ANTHROPIC_API_KEY   - Claude API key (console.anthropic.com)
 *   GITHUB_TOKEN         - a GitHub personal access token (fine-grained, least privilege)
 *   COMPOSIO_API_KEY     - your Composio project API key
 *
 * Required vars (set in wrangler.toml, not secret):
 *   FIREBASE_PROJECT_ID  - e.g. "nexus-web-development-official"
 *   OWNER_EMAIL           - e.g. "brodywilliams0226@gmail.com"
 *   CLAUDE_MODEL          - optional override, defaults to claude-sonnet-5-5
 *   COMPOSIO_USER_ID      - optional, the Composio entity/user id your apps are connected under
 */

import { createRemoteJWKSet, jwtVerify } from 'jose';

const FIREBASE_JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const jwks = createRemoteJWKSet(new URL(FIREBASE_JWKS_URL));

const CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_MODEL = 'claude-sonnet-5-5';

const GITHUB_API = 'https://api.github.com';
const COMPOSIO_API = 'https://backend.composio.dev/api/v3';

const SYSTEM_PROMPT = `You are Nexus, a private voice assistant that only ever talks to your one owner, Brody.
You have tools to read and act on his GitHub account and on whatever apps he has connected through Composio (Gmail, Calendar, Slack, Notion, etc. - only the ones actually connected will work).

Rules:
- Before calling composio_execute_tool, call composio_find_tools first to find the exact tool slug and its required arguments, unless you already found it earlier in this same conversation.
- Never guess at a GitHub path or a Composio tool slug - look it up or ask a clarifying question in your reply instead.
- If a tool call errors (not connected, missing scope, bad input), say so plainly rather than inventing an answer.
- Your reply is read aloud by a speech synthesizer and shown as plain text. Write it as short, natural spoken sentences: no markdown, no bullet points, no headers, no asterisks. Summarize instead of listing raw data.`;

const TOOLS = [
  {
    name: 'github_api',
    description:
      "Call GitHub's REST API on the owner's behalf (already authenticated server-side). Use for reading or writing repos, issues, pull requests, commits, notifications, workflow runs, etc.",
    input_schema: {
      type: 'object',
      properties: {
        method: { type: 'string', enum: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'] },
        path: {
          type: 'string',
          description:
            'Path after https://api.github.com, e.g. "/user/repos", "/repos/owner/repo/issues", "/notifications"',
        },
        body: { type: 'object', description: 'JSON body for POST/PATCH/PUT requests' },
      },
      required: ['method', 'path'],
    },
  },
  {
    name: 'composio_find_tools',
    description:
      'Search the catalog of Composio tools/actions (Gmail, Google Calendar, Slack, Notion, and whatever else is connected) by keyword or toolkit, to find the exact tool slug and its input schema before executing it.',
    input_schema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Free text, e.g. "send email" or "list calendar events today"' },
        toolkit: {
          type: 'string',
          description: 'Optional toolkit slug to narrow results, e.g. "gmail", "googlecalendar", "slack", "notion"',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'composio_execute_tool',
    description:
      "Execute one specific Composio tool slug (found via composio_find_tools) with arguments, against the owner's connected account for that app.",
    input_schema: {
      type: 'object',
      properties: {
        tool_slug: { type: 'string', description: 'Exact slug from composio_find_tools, e.g. "GMAIL_SEND_EMAIL"' },
        arguments: { type: 'object', description: "Arguments matching that tool's input schema" },
      },
      required: ['tool_slug', 'arguments'],
    },
  },
];

function corsHeaders() {
  return {
    // Tighten this to your actual site origin once it has a fixed URL/domain.
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

/** Verifies the Firebase ID token on the request and that it belongs to the owner. */
async function verifyOwner(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) throw new Error('Missing bearer token');

  const { payload } = await jwtVerify(match[1], jwks, {
    issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
    audience: env.FIREBASE_PROJECT_ID,
  });

  if (!payload.email_verified) throw new Error('Email not verified');
  if ((payload.email || '').toLowerCase() !== env.OWNER_EMAIL.toLowerCase()) {
    throw new Error('Token does not belong to the owner');
  }
  return payload;
}

async function runGithubApi({ method, path, body }, env) {
  if (!env.GITHUB_TOKEN) return { error: 'GITHUB_TOKEN is not configured on the worker' };
  const url = path.startsWith('http') ? path : `${GITHUB_API}${path.startsWith('/') ? '' : '/'}${path}`;
  const resp = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'nexus-assistant-worker',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await resp.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: resp.status, data };
}

async function composioFindTools({ query, toolkit }, env) {
  if (!env.COMPOSIO_API_KEY) return { error: 'COMPOSIO_API_KEY is not configured on the worker' };
  const params = new URLSearchParams({ query, limit: '10', toolkit_versions: 'latest' });
  if (toolkit) params.set('toolkit_slug', toolkit);

  const resp = await fetch(`${COMPOSIO_API}/tools?${params}`, {
    headers: { 'x-api-key': env.COMPOSIO_API_KEY },
  });
  if (!resp.ok) return { status: resp.status, error: await resp.text() };

  const data = await resp.json();
  return (data.items || []).map((t) => ({
    slug: t.slug,
    description: t.description || t.human_description,
    input_parameters: t.input_parameters,
  }));
}

async function composioExecuteTool({ tool_slug, arguments: args }, env) {
  if (!env.COMPOSIO_API_KEY) return { error: 'COMPOSIO_API_KEY is not configured on the worker' };
  const resp = await fetch(`${COMPOSIO_API}/tools/execute/${tool_slug}`, {
    method: 'POST',
    headers: {
      'x-api-key': env.COMPOSIO_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      user_id: env.COMPOSIO_USER_ID || 'default',
      arguments: args,
    }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) return { status: resp.status, error: data };
  return data;
}

async function callClaude(messages, env) {
  const resp = await fetch(CLAUDE_API_URL, {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': ANTHROPIC_VERSION,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.CLAUDE_MODEL || DEFAULT_MODEL,
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      tools: TOOLS,
      messages,
    }),
  });
  if (!resp.ok) {
    throw new Error(`Claude API error ${resp.status}: ${await resp.text()}`);
  }
  return resp.json();
}

/** Runs the think -> call tool -> think loop until Claude gives a final text reply. */
async function handlePrompt(prompt, env) {
  const messages = [{ role: 'user', content: prompt }];

  for (let turn = 0; turn < 6; turn++) {
    const result = await callClaude(messages, env);

    if (result.stop_reason !== 'tool_use') {
      const textBlock = result.content.find((b) => b.type === 'text');
      return textBlock ? textBlock.text : "I didn't get a usable reply from Claude.";
    }

    messages.push({ role: 'assistant', content: result.content });

    const toolResults = [];
    for (const block of result.content) {
      if (block.type !== 'tool_use') continue;
      let output;
      try {
        if (block.name === 'github_api') output = await runGithubApi(block.input, env);
        else if (block.name === 'composio_find_tools') output = await composioFindTools(block.input, env);
        else if (block.name === 'composio_execute_tool') output = await composioExecuteTool(block.input, env);
        else output = { error: `Unknown tool: ${block.name}` };
      } catch (err) {
        output = { error: String(err && err.message ? err.message : err) };
      }
      toolResults.push({
        type: 'tool_result',
        tool_use_id: block.id,
        content: JSON.stringify(output).slice(0, 8000),
      });
    }
    messages.push({ role: 'user', content: toolResults });
  }

  return 'That request needed too many steps - try breaking it into something smaller.';
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405);
    }

    try {
      await verifyOwner(request, env);
    } catch (err) {
      return json({ error: `Unauthorized: ${err.message}` }, 401);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400);
    }

    const prompt = (body.prompt || '').toString().trim();
    if (!prompt) return json({ error: 'Missing prompt' }, 400);
    if (!env.ANTHROPIC_API_KEY) return json({ error: 'ANTHROPIC_API_KEY is not configured on the worker' }, 500);

    try {
      const reply = await handlePrompt(prompt, env);
      return json({ reply });
    } catch (err) {
      console.error(err);
      return json({ error: 'Internal error processing command' }, 500);
    }
  },
};
