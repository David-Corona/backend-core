import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppLoggerModule } from '../logger/logger.module';
import { loadEnvConfig } from '../config/env.config';
import { PrismaModule } from '../prisma/prisma.module';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [loadEnvConfig],
    }),
    AppLoggerModule,
    PrismaModule
  ],
  exports: [PrismaModule, AppLoggerModule, ConfigModule],
})
export class CoreModule {}