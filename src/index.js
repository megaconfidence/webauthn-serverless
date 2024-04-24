import { Hono } from 'hono';
import manifest from '__STATIC_CONTENT_MANIFEST';
import { serveStatic } from 'hono/cloudflare-workers';
import { sessionMiddleware, CookieStore, Session } from 'hono-sessions';
import {
	verifyRegistrationResponse,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	generateAuthenticationOptions,
} from '@simplewebauthn/server';

const app = new Hono();

const store = new CookieStore();

app.use(
	'*',
	sessionMiddleware({
		store,
		encryptionKey: 'password_at_least_32_characters_long', // Required for CookieStore, recommended for others
		expireAfterSeconds: 900, // Expire session after 15 minutes of inactivity
		cookieOptions: {
			sameSite: 'Lax', // Recommended for basic CSRF protection in modern browsers
			path: '/', // Required for this library to work properly
			httpOnly: true, // Recommended to avoid XSS attacks
		},
	})
);

let isConfigured = false;
let rpID = '';
let expectedOrigin = '';
let rpName = 'WebAuthn Tutorial';

function setParams(url) {
	if (isConfigured) return;
	const { origin, hostname } = new URL(url);
	rpID = hostname;
	expectedOrigin = origin;
	isConfigured = true;
}

app.post('/register', async (c) => {
	console.log(c.env);
	setParams(c.req.url);

	const uname = (await c.req.json()).username;
	const user = JSON.parse(await c.env.KV.get(uname)) || {
		passKeys: [],
		username: uname,
	};

	const { username: userName, passKeys } = user;

	const opts = {
		rpID,
		rpName,
		userName,
		attestationType: 'none',
		supportedAlgorithmIDs: [-7, -257],
		authenticatorSelection: {
			residentKey: 'discouraged',
		},
		excludeCredentials: passKeys?.map((key) => ({
			id: key.id,
			transports: key.transports,
		})),
	};
	const options = await generateRegistrationOptions(opts);

	const session = c.get('session');
	session.set('challenge', JSON.stringify({ user, options }));
	return c.json(options);
});

app.post('/register/complete', async (c) => {
	const response = await c.req.json();
	const session = c.get('session');

	const { options, user } = JSON.parse(session.get('challenge'));

	const opts = {
		response,
		expectedOrigin,
		expectedRPID: rpID,
		requireUserVerification: false, //Enforce user verification by the authenticator
		expectedChallenge: options.challenge,
	};

	let verification;
	try {
		verification = await verifyRegistrationResponse(opts);
	} catch (error) {
		console.error(error);
		c.status(400);
		return c.json({ error: error.message });
	}

	const { verified, registrationInfo } = verification;

	if (verified && registrationInfo) {
		const { counter, credentialID, credentialBackedUp, credentialPublicKey, credentialDeviceType } = registrationInfo;

		const passKey = user.passKeys.find((key) => key.id === credentialID);

		if (!passKey) {
			user.passKeys.push({
				counter,
				id: credentialID,
				backedUp: credentialBackedUp,
				webAuthnUserID: options.user.id,
				deviceType: credentialDeviceType,
				transports: response.response.transports,
				credentialPublicKey: Array.from(credentialPublicKey),
			});
		}
		await c.env.KV.put(user.username, JSON.stringify(user));
	}

	session.set('challenge', null);
	return c.json({ verified });
});

app.post('/login', async (c) => {
	const user = JSON.parse(await c.env.KV.get((await c.req.json()).username));

	const opts = {
		rpID,
		allowCredentials: user?.passKeys.map((key) => ({
			id: key.id,
			transports: key.transports,
		})),
	};
	const options = await generateAuthenticationOptions(opts);

	const session = c.get('session');
	session.set('challenge', JSON.stringify({ user, options }));
	return c.json(options);
});

app.post('/login/complete', async (c) => {
	const body = await c.req.json();
	const session = c.get('session');

	const { options, user } = JSON.parse(session.get('challenge'));

	const passKey = user.passKeys.find((key) => key.id === body.id);
	if (!passKey) {
		c.status(400);
		return c.json({ error: `Could not find passkey ${body.id} for user ${user.id}` });
	}

	const opts = {
		response: body,
		expectedOrigin,
		expectedRPID: rpID,
		authenticator: passKey,
		requireUserVerification: false,
		expectedChallenge: options.challenge,
	};

	let verification;
	try {
		verification = await verifyAuthenticationResponse(opts);
	} catch (error) {
		console.error(error);
		c.status(400);
		return c.json({ error: error.message });
	}

	const { verified, authenticationInfo } = verification;

	if (verified) {
		passKey.counter = authenticationInfo.newCounter;
		user.passKeys = user.passKeys.map((i) => (i.id == passKey.id ? passKey : i));
		await c.env.KV.put(user.username, JSON.stringify(user));
	}

	session.set('challenge', null);
	return c.json({ verified });
});

app.get('/*', serveStatic({ root: './', manifest }));

export default app;
