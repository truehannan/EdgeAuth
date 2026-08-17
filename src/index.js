import { Hono } from 'hono';
import renderHomepage from './views/home';
import renderScannerPage from './views/scanner';
import generateTotp from './utils/generateTotp';
import { encrypt, decrypt } from './utils/storeKey';
import renderDbManager from './views/db_manager';

const app = new Hono();

app.get('/', async (c) => {
	// get all the tokens from the database
	const { results: tokens } = await c.env.DB.prepare(`SELECT * FROM Tokens`).all();

	// iterate over the tokens and generate the totp
	let results = [];
	for (let token of tokens) {
		const secret = await decrypt({
			base64Combined: token.EncryptedSecret,
			key: c.env.ENCRYPTION_KEY,
		});

		// generate totp
		const otp = await generateTotp({
			algorithm: token.Algorithm,
			digits: token.Digits,
			period: token.TimeStep,
			secret,
		});

		results.push({
			issuer: token.Issuer,
			otp,
			timeStep: token.TimeStep,
		});
	}

	return c.render(renderHomepage({ tokens: results }));
});

app.get('/scan', async (c) => {
	return c.render(renderScannerPage());
});

app.get('/db_manager', async (c) => {
	return c.render(renderDbManager());
});

// generate a totp token before storing it
app.post('/api/token/new', async (c) => {
	const { algorithm, digits, issuer, label, secret, period } = await c.req.json();

	const otp = await generateTotp({
		algorithm,
		digits,
		period,
		secret,
	});

	// calculate the code and show the code in the user
	return c.json({
		code: otp,
	});
});

// save the token to the database
app.post('/api/token/save', async (c) => {
	const { algorithm, digits, issuer, label, secret, period } = await c.req.json();

	// encrypt the secret
	const encryptedSecret = await encrypt({
		data: secret,
		keyB64: c.env.ENCRYPTION_KEY,
	});

	// check if the issuer already exist in the database, then update the token
	const { results: issuerExists } = await c.env.DB.prepare(`SELECT * FROM Tokens WHERE Issuer = ?`).bind(issuer).all();
	if (issuerExists.length > 0) {
		const { result } = await c.env.DB.prepare(
			`UPDATE Tokens SET TimeStep = ?, EncryptedSecret = ?, Algorithm = ?, Digits = ? WHERE Issuer = ?`,
		)
			.bind(period, encryptedSecret, algorithm, digits, issuer)
			.all();
		return c.json({
			info: 'Issuer already exists, updated the token.',
		});
	}

	// insert the token to the database
	const { result } = await c.env.DB.prepare(
		`INSERT INTO Tokens (Issuer, TimeStep, EncryptedSecret, Algorithm, Digits) VALUES (?, ?, ?, ?, ?)`,
	)
		.bind(issuer, period, encryptedSecret, algorithm, digits)
		.all();
	return c.json({
		info: 'Token saved successfully.',
	});
});

// creates a dump of current tokens table
app.get('/api/db/dump', async (c) => {
	try {
		// fetch all rows from the table
		const { results } = await c.env.DB.prepare(`SELECT * FROM Tokens`).all();

		const jsonString = JSON.stringify(results, null, 2);

		const file = new Blob([jsonString], { type: 'application/json' });

		return new Response(file, {
			headers: {
				'Content-Type': 'application/json',
				'Content-Disposition': 'attachment; filename="tokens-dump.json"', // Forces download as a file
			},
		});
	} catch (e) {
		console.log(e);
		return c.json({
			err: e.message,
		});
	}
});

export default app;
