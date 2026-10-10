// Recognition only. These entries do not add code-aware framework/CWE support.
export const frameworkPackages: Readonly<Record<string, string>> = {
  express: 'express', fastify: 'fastify', koa: 'koa', '@hapi/hapi': 'hapi',
  '@nestjs/core': 'nestjs', next: 'nextjs', nuxt: 'nuxt', '@sveltejs/kit': 'sveltekit',
  '@adonisjs/core': 'adonisjs', hono: 'hono',
};

export const databasePackages: Readonly<Record<string, string>> = {
  'better-sqlite3': 'sqlite', sqlite3: 'sqlite', sqlite: 'sqlite',
  pg: 'postgresql', postgres: 'postgresql', 'pg-promise': 'postgresql',
  mysql: 'mysql', mysql2: 'mysql', mariadb: 'mariadb',
  mongodb: 'mongodb', mongoose: 'mongodb', mssql: 'sqlserver',
  redis: 'redis', ioredis: 'redis',
};

export const ormPackages = new Set([
  '@prisma/client', 'prisma', 'typeorm', 'sequelize', 'knex', 'objection',
  'drizzle-orm', 'mongoose', '@mikro-orm/core',
]);

export const authenticationPackages: Readonly<Record<string, 'session' | 'jwt' | 'passport' | 'auth-provider'>> = {
  'express-session': 'session', 'cookie-session': 'session', '@fastify/session': 'session',
  '@fastify/secure-session': 'session', 'koa-session': 'session',
  jsonwebtoken: 'jwt', jose: 'jwt', 'express-jwt': 'jwt', '@fastify/jwt': 'jwt',
  passport: 'passport', 'passport-local': 'passport', 'passport-jwt': 'jwt',
  'express-openid-connect': 'auth-provider', 'next-auth': 'auth-provider',
  '@auth/core': 'auth-provider', '@clerk/express': 'auth-provider',
};

export const middlewarePackages: Readonly<Record<string, 'cors' | 'session' | 'cookie'>> = {
  cors: 'cors', '@fastify/cors': 'cors', '@koa/cors': 'cors',
  'express-session': 'session', 'cookie-session': 'session', 'koa-session': 'session',
  '@fastify/session': 'session', '@fastify/secure-session': 'session',
  'cookie-parser': 'cookie', '@fastify/cookie': 'cookie',
};
