import { Hono } from 'hono';
import manifest from '__STATIC_CONTENT_MANIFEST';
import { serveStatic } from 'hono/cloudflare-workers';

const app = new Hono();

app.get('/*', serveStatic({ root: './', manifest }));

export default app;
