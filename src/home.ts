import { validateAccessJWT } from './jwt';

function escapeHtml(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const STYLE = `<style>
body { font-family: system-ui, sans-serif; max-width: 480px; margin: 2rem auto; padding: 0 1rem; }
label { display: block; margin: 0.5rem 0; }
input { padding: 0.3rem; width: 100%; box-sizing: border-box; }
button { margin-top: 0.75rem; padding: 0.4rem 1rem; }
p { padding: 0.5rem; background: #eef; border-radius: 4px; }
</style>`;

function htmlResponse(body: string, status = 200): Response {
	return new Response(
		`<!DOCTYPE html>\n<html>\n<head><title>Shortener</title>${STYLE}</head>\n<body>${body}</body>\n</html>`,
		{ status, headers: { 'Content-Type': 'text/html;charset=UTF-8' } },
	);
}

function formPage(message?: string, status = 200): Response {
	const messageHtml = message ? `<p>${message}</p>\n` : '';
	return htmlResponse(
		`<h1>Create Short URL</h1>\n${messageHtml}<form method="POST">\n` +
			`<label>Slug: <input type="text" name="slug" required></label><br>\n` +
			`<label>URL: <input type="text" name="url" required></label><br>\n` +
			`<button type="submit">Create</button>\n</form>`,
		status,
	);
}

export async function handleHomePage(request: Request, env: Env): Promise<Response> {
	if (!env.CF_ACCESS_AUD || !env.CF_ACCESS_JWKS_URL) {
		return htmlResponse('Niente');
	}

	const token = request.headers.get('Cf-Access-Jwt-Assertion');
	if (!token) {
		return new Response('Forbidden', { status: 403 });
	}
	try {
		await validateAccessJWT(token, env.CF_ACCESS_JWKS_URL, env.CF_ACCESS_AUD);
	} catch {
		return new Response('Forbidden', { status: 403 });
	}

	if (request.method === 'GET') {
		return formPage();
	}

	if (request.method === 'POST') {
		const formData = await request.formData();
		const slug = formData.get('slug');
		const url = formData.get('url');

		if (!slug || !url || typeof slug !== 'string' || typeof url !== 'string') {
			return formPage('Error: both slug and URL are required.', 400);
		}

		await env.SHORT_URLS.put(slug, url);
		return formPage(`Created: /${escapeHtml(slug)} &rarr; ${escapeHtml(url)}`);
	}

	return new Response('Method Not Allowed', { status: 405 });
}
