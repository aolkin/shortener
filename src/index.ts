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

function parseDataURL(dataURL: string) {
  const parts = dataURL.split(',');
  if (parts.length < 2) {
    return null; // Not a valid data URL format
  }

  const metadata = parts[0].substring(5); // Remove "data:" prefix
  const data = parts.slice(1).join(','); // Rejoin in case data contains commas

  let mediaType = '';
  let isBase64 = false;

  const metadataParts = metadata.split(';');
  mediaType = metadataParts[0];

  if (metadataParts.includes('base64')) {
    isBase64 = true;
  }

  return {
    mediaType: mediaType,
    data: isBase64 ? atob(data) : decodeURIComponent(data),
  };
}

export default {
	async fetch(
		request: Request,
		env: Env,
		_ctx: ExecutionContext
	): Promise<Response> {
		const url = new URL(request.url);

		const pathname = url.pathname.slice(1);

		if (!pathname) {
			return new Response(
				'Bad Request',
				{ status: 400 }
			);
		}

		const redirectURL = await env.SHORT_URLS.get(pathname);

		if (!redirectURL) {
			return new Response(
				'Not Found',
				{ status: 404 }
			);
		}

		if (redirectURL.startsWith('data:')) {
			const parsedData = parseDataURL(redirectURL);
			if (parsedData) {
				return new Response(
					parsedData.data,
					{
						headers: {
							'Content-Type': parsedData.mediaType,
						},
					}
				);
			}
		
		return Response.redirect(redirectURL.startsWith('http') ? redirectURL : `https://${redirectURL}`, 302);
	},
} satisfies ExportedHandler<Env>;
