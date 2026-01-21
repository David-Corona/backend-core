import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { loadEnvConfig } from './config/env.config';
import { AppLoggerModule } from './logger/logger.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [loadEnvConfig],
    }),
    AppLoggerModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
