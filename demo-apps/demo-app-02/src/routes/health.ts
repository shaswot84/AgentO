import type { FastifyPluginAsync } from 'fastify';

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get('/health', async () => {
    return {
      status: 'pass',
      service: 'demo-app-02',
      framework: 'fastify',
      timestamp: new Date().toISOString(),
    };
  });
};
