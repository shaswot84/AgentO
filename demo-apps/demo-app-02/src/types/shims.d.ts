declare module '@prisma/client' {
  export interface PrismaClient {
    $connect(): Promise<void>;
  }
}
