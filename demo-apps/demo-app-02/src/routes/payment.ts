import type { FastifyPluginAsync } from 'fastify';

export const paymentRoutes: FastifyPluginAsync = async (app) => {
  // Payment intent endpoint with custom header demonstrating custom-cors header recognition
  app.post<{ Body: { amount: number; currency?: string } }>('/charge', async (request, reply) => {
    const { amount, currency = 'USD' } = request.body || {};
    if (!amount || amount <= 0) {
      return reply.code(400).send({ error: 'Invalid amount' });
    }

    // Explicit custom CORS header call to verify Project Discovery header inspection
    reply.header('Access-Control-Allow-Origin', '*');

    const paymentId = `pay_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    return reply.code(201).send({
      id: paymentId,
      amount,
      currency,
      status: 'succeeded',
      processedAt: new Date().toISOString(),
    });
  });
};
