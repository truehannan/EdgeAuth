import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

describe('EdgeAuth routes', () => {
	it('allows public access to scanner page', async () => {
		const request = new Request('http://example.com/scan');
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(await response.text()).toContain('Scan QR Code');
	});

	it('returns not found for removed login route', async () => {
		const response = await SELF.fetch('http://example.com/login');
		expect(response.status).toBe(404);
	});

	it('keeps token generation endpoint working without auth', async () => {
		const response = await SELF.fetch('http://example.com/api/token/new', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				algorithm: 'SHA1',
				digits: 6,
				issuer: 'Example',
				label: 'user@example.com',
				secret: 'JBSWY3DPEHPK3PXP',
				period: 30,
			}),
		});

		expect(response.status).toBe(200);
		const payload = await response.json();
		expect(payload).toHaveProperty('code');
		expect(payload.code).toMatch(/^\d{6}$/);
	});
});
