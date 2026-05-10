const reported = new Set<string>();
setInterval(() => reported.clear(), 5 * 60 * 1000);

export function reportError(opts: { repo: string; token: string; error: unknown; route: string | null; url: string; status: number }) {
	if (opts.status === 404) return;
	const id = Bun.randomUUIDv7();
	const err = opts.error instanceof Error ? opts.error : new Error(String(opts.error));
	console.error(`[server-error] ${id}`, err);

	const title = `[Production Error] ${err.message.slice(0, 120)}`;
	if (reported.has(title)) return;
	reported.add(title);

	const api = `https://api.github.com/repos/${opts.repo}`;
	const body = [`**ID:** \`${id}\``, `**Status:** \`${opts.status}\``, `**Route:** \`${opts.route ?? 'unknown'}\``, `**URL:** \`${opts.url}\``, '', '```', err.stack ?? err.message, '```'].join('\n');

	const headers = {
		Authorization: `token ${opts.token}`,
		Accept: 'application/vnd.github+json',
		'Content-Type': 'application/json',
	};

	fetch(`${api}/issues?state=open&labels=auto-error&per_page=100`, { headers })
		.then((r) => r.json())
		.then((issues: unknown) => {
			if (!Array.isArray(issues)) return;
			const existing = (issues as Array<{ title: string; number: number }>).find((i) => i.title === title);
			const [url, payload] = existing ? [`${api}/issues/${existing.number}/comments`, { body: `**Re-occurrence**\n\n${body}` }] : [`${api}/issues`, { title, body, labels: ['auto-error'] }];
			return fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) });
		})
		.catch((e) => console.error('[error-reporter]', e));
}
