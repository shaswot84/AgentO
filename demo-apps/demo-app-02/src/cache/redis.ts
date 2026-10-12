import { Redis } from 'ioredis';

// Runtime cache client with lazy connection
export const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  lazyConnect: true,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 0,
});
