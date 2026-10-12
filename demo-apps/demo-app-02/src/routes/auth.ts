import type { FastifyPluginAsync } from 'fastify';

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Body: { username: string; role?: string } }>('/token', async (request, reply) => {
    const { username, role = 'customer' } = request.body || {};
    if (!username) {
      return reply.code(400).send({ error: 'Username is required' });
    }

    const token = app.jwt.sign({
      sub: username,
      role,
      iss: 'demo-app-02',
    });

    reply.setCookie('token', token, {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
    });

    return reply.send({ token, username, role });
  });

  app.get('/verify', {
    onRequest: [async (request, reply) => {
      try {
        await request.jwtVerify();
      } catch {
        return reply.code(401).send({ error: 'Unauthorized token' });
      }
    }],
  }, async (request) => {
    return { authenticated: true, user: request.user };
  });
};
