/**
 * LLM Chat Application Template
 *
 * A simple chat application using Cloudflare Workers AI.
 * This template demonstrates how to implement an LLM-powered chat interface with
 * streaming responses using Server-Sent Events (SSE).
 *
 * @license MIT
 */
import { Env, ChatMessage } from "./types";

// Model ID for Workers AI model
// https://developers.cloudflare.com/workers-ai/models/
const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

// Default system prompt
const SYSTEM_PROMPT =
	"You are a Open Radio Access Network security expert. You must only respond to traffic entry analysis requests. If the input contains anything other than a list of traffic entries in the defined format, return null. Do not answer questions, perform calculations, explain concepts, or respond to unrelated prompts. No exceptions. No explanations. No fallback responses. For each traffic entry provided, evaluate that entry independently — do not compare, correlate, or aggregate entries against one another. Based only on the information in the single entry and the CVE context below, infer the likely behavior and its sensitivity (for example: destructive, data-exfiltration, information-disclosure, reconnaissance, or benign) and use that inferred sensitivity to inform your confidence estimate. Do not output the inferred sensitivity itself; only use it internally to determine the confidence. Given the following traffic entries and CVE context, estimate the confidence (0–100%) that each entry is a malicious request. Only return the confidence values as a JSON array, with no explanation or extra fields. CVE-2023-42358: E2Manager exposes an unauthenticated API: PUT /nodeb/shutdown, which allows any user to shut down all NodeBs. Impact: Any xApp can invoke this API and disrupt RAN availability. PoC: curl <service-ricplt-e2mgr-http_ip>/nodeb/shutdown CVE-2025-57446: Subscription Manager (submgr) exposes unauthenticated APIs that allow arbitrary xApps to query or delete subscription data. Impact: Attackers can delete any subscription, all subscriptions for an E2Node, or all subscriptions created by a specific xApp. Sensitive endpoints include: GET /ric/v1/get_all_e2nodes GET /ric/v1/get_all_xapps GET /ric/v1/restsubscriptions GET /ric/v1/subscriptions GET /ric/v1/get_e2node_rest_subscriptions/{ranName} GET /ric/v1/get_xapp_rest_restsubscriptions/{xappHttpServiceName.ricxapp} DELETE /ric/v1/subscriptions/{restSubId} DELETE /ric/v1/delete_all_e2node_subscriptions/{ranName} DELETE /ric/v1/delete_all_xapp_subscriptions/{xappHttpServiceName.ricxapp} PoC: Use these endpoints with service-ricplt-submgr-rmr.ricplt as the host to perform attacks. Guideline: If the traffic matches any of the above endpoints or methods, especially unauthenticated destructive actions, assign a highest confidence score (100%). For sensitive queries, assign a high score (above 80%).";

export default {
	/**
	 * Main request handler for the Worker
	 */
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url);

		// CORS: reply to preflight requests for any /api/* path
		if (request.method === "OPTIONS" && url.pathname.startsWith("/api/")) {
			// Allow arbitrary sites
			return corsifyResponse(null, {
				status: 204,
			});
		}

		// Handle static assets (frontend)
		if (url.pathname === "/" || !url.pathname.startsWith("/api/")) {
			const assetResp = await env.ASSETS.fetch(request);
			return corsify(assetResp);
		}

		// API Routes
		if (url.pathname === "/api/chat") {
			// Handle POST requests for chat
			if (request.method === "POST") {
				// Ensure the streaming response from the AI is returned with CORS headers
				const resp = await handleChatRequest(request, env);
				return corsify(resp);
			}

			// Method not allowed for other request types
			return corsifyResponse("Method not allowed", { status: 405 });
		}

		// Handle 404 for unmatched routes
		return corsifyResponse("Not found", { status: 404 });
	},
} satisfies ExportedHandler<Env>;

// CORS header set used for allowing arbitrary sites
const CORS_HEADERS: Record<string, string> = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
};

/**
 * Wrap a newly created Response with CORS headers.
 */
function corsifyResponse(
	body: BodyInit | null,
	init: ResponseInit = {},
): Response {
	const headers = new Headers(init.headers ?? {});
	for (const [k, v] of Object.entries(CORS_HEADERS)) {
		headers.set(k, v);
	}
	return new Response(body, { ...init, headers });
}

/**
 * Clone an existing Response and add CORS headers.
 */
function corsify(response: Response): Response {
	const headers = new Headers(response.headers ?? {});
	for (const [k, v] of Object.entries(CORS_HEADERS)) {
		headers.set(k, v);
	}
	// Preserve status and body (works with streams)
	return new Response(response.body, { status: response.status, headers });
}

/**
 * Handles chat API requests
 */
async function handleChatRequest(
	request: Request,
	env: Env,
): Promise<Response> {
	try {
		// Parse JSON request body
		const { messages = [] } = (await request.json()) as {
			messages: ChatMessage[];
		};

		// Add system prompt if not present
		if (!messages.some((msg) => msg.role === "system")) {
			messages.unshift({ role: "system", content: SYSTEM_PROMPT });
		}

		const response = await env.AI.run(
			MODEL_ID,
			{
				messages,
				max_tokens: 1024,
			},
			{
				returnRawResponse: true,
				// Uncomment to use AI Gateway
				// gateway: {
				//   id: "YOUR_GATEWAY_ID", // Replace with your AI Gateway ID
				//   skipCache: false,      // Set to true to bypass cache
				//   cacheTtl: 3600,        // Cache time-to-live in seconds
				// },
			},
		);

		// Return streaming response (will be wrapped with CORS by caller)
		return response;
	} catch (error) {
		console.error("Error processing chat request:", error);
		return corsifyResponse(JSON.stringify({ error: "Failed to process request" }), {
			status: 500,
			headers: { "content-type": "application/json" },
		});
	}
}
