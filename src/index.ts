/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
	async fetch(
		request: Request,
		env: Env,
		_ctx: ExecutionContext
	): Promise<Response> {
		const url = new URL(request.url);

		const pathname = url.pathname.slice(1);

		const redirectURL = await env.SHORT_URLS.get(pathname);

		if (!redirectURL) {
			return new Response(
				'Not Found',
				{ status: 404 }
			);
		}

		return Response.redirect(redirectURL.startsWith('http') ? redirectURL : `https://${redirectURL}`, 302);
	},
} satisfies ExportedHandler<Env>;
