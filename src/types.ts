/**
 * Type definitions for the LLM chat application.
 */

export interface Env {
	/**
	 * Binding for the Workers AI API.
	 */
	AI: Ai;

	/**
	 * Binding for static assets.
	 */
	ASSETS: { fetch: (request: Request) => Promise<Response> };

	/**
	 * Optional KV namespace for feature flags. Bind a KV namespace named
	 * FEATURE_FLAGS in your wrangler / Cloudflare dashboard to use it.
	 */
	FEATURE_FLAGS?: KVNamespace;
}

/**
 * Represents a chat message.
 */
export interface ChatMessage {
	role: "system" | "user" | "assistant";
	content: string;
}
