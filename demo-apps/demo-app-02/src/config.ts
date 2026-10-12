export interface AppConfig {
  port: number;
  host: string;
  jwtSecret: string;
  corsOrigin: string;
  databaseUrl: string;
  redisUrl: string;
}

export const config: AppConfig = {
  port: Number(process.env.PORT) || 4000,
  host: process.env.HOST || '0.0.0.0',
  jwtSecret: process.env.JWT_SECRET || 'demo-app-02-super-secret-jwt-key-2026',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:4000',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://demo:secret@localhost:5432/demodb',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
};
