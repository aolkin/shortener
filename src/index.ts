import { handleHomePage } from './home';

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
    data: isBase64 ? Uint8Array.from(atob(data), c => c.charCodeAt(0)) : decodeURIComponent(data),
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
			return handleHomePage(request, env);
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
		}
		
		return Response.redirect(redirectURL.startsWith('http') ? redirectURL : `https://${redirectURL}`, 302);
	},
} satisfies ExportedHandler<Env>;
