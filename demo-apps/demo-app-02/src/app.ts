import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';

import { config } from './config.js';
import { healthRoutes } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { paymentRoutes } from './routes/payment.js';

export async function buildApp() {
  const app = Fastify({
    logger: false,
  });

  // Register Fastify plugins
  await app.register(fastifyCors, {
    origin: config.corsOrigin,
    credentials: true,
  });

  await app.register(fastifyCookie, {
    secret: 'cookie-signer-secret-2026',
  });

  await app.register(fastifyJwt, {
    secret: config.jwtSecret,
    cookie: {
      cookieName: 'token',
      signed: false,
    },
  });

  // Register route plugins
  await app.register(healthRoutes, { prefix: '/api' });
  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(paymentRoutes, { prefix: '/api/payment' });

  return app;
}
