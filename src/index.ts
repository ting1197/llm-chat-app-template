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
	"You are a Open Radio Access Network security expert. You must only respond to traffic entry analysis requests. If the input contains anything other than a list of traffic entries in the defined format, return null. Do not answer questions, perform calculations, explain concepts, or respond to unrelated prompts. No exceptions. No explanations. No fallback responses. Given the following traffic entries and CVE context, estimate the confidence (0–100%) that each entry is a malicious request. Only return the confidence values as a JSON array, no explanation. CVE-2023-42358: E2Manager exposes an unauthenticated API: PUT /nodeb/shutdown, which allows any user to shut down all NodeBs. Impact: Any xApp can invoke this API and disrupt RAN availability. PoC: curl <service-ricplt-e2mgr-http_ip>/nodeb/shutdown CVE-2025-57446: Subscription Manager (submgr) exposes unauthenticated APIs that allow arbitrary xApps to query or delete subscription data. Impact: Attackers can delete any subscription, all subscriptions for an E2Node, or all subscriptions created by a specific xApp. Sensitive endpoints include: GET /ric/v1/get_all_e2nodes GET /ric/v1/get_all_xapps GET /ric/v1/restsubscriptions GET /ric/v1/subscriptions GET /ric/v1/get_e2node_rest_subscriptions/{ranName} GET /ric/v1/get_xapp_rest_restsubscriptions/{xappHttpServiceName.ricxapp} DELETE /ric/v1/subscriptions/{restSubId} DELETE /ric/v1/delete_all_e2node_subscriptions/{ranName} DELETE /ric/v1/delete_all_xapp_subscriptions/{xappHttpServiceName.ricxapp} PoC: Use these endpoints with service-ricplt-submgr-rmr.ricplt as the host to perform attacks. Guideline: If the traffic matches any of the above endpoints or methods, especially unauthenticated destructive actions, assign a highest confidence score (100%). For sensitive queries, assign a high score (above 80%).";

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

		// Handle static assets (frontend)
		if (url.pathname === "/" || !url.pathname.startsWith("/api/")) {
			return env.ASSETS.fetch(request);
		}

		// API Routes
		if (url.pathname === "/api/chat") {
			// Handle POST requests for chat
			if (request.method === "POST") {
				return handleChatRequest(request, env);
			}

			// Method not allowed for other request types
			return new Response("Method not allowed", { status: 405 });
		}

		// Handle 404 for unmatched routes
		return new Response("Not found", { status: 404 });
	},
} satisfies ExportedHandler<Env>;

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

		// Return streaming response
		return response;
	} catch (error) {
		console.error("Error processing chat request:", error);
		return new Response(
			JSON.stringify({ error: "Failed to process request" }),
			{
				status: 500,
				headers: { "content-type": "application/json" },
			},
		);
	}
}
