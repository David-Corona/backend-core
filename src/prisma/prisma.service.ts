import 'dotenv/config';
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg'

/* 
  The Prisma Client is wrapped in a PrismaService. 
  Single instance for the entire app.
  Connected on startup, disconnected on shutdown.
*/
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {

  constructor() {
    // Prisma Client must be constructed with an adapter that acts as a translator between the Client and the JS database driver
    const adapter = new PrismaPg({
      connectionString: process.env.DATABASE_URL!,
    });
    super({ adapter });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
