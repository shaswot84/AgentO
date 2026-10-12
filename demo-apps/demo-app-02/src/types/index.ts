// Type-only import to verify Project Discovery ignores non-runtime types
import type { PrismaClient } from '@prisma/client';

export type UnusedPrismaReference = PrismaClient | null;

export interface UserSession {
  userId: string;
  email: string;
  role: string;
}

export interface TransactionRecord {
  id: string;
  userId: string;
  amount: number;
  currency: string;
  createdAt: string;
}
