import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import { createPinoConfig } from './logger.config';

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: createPinoConfig(),
    }),
  ],
})
export class AppLoggerModule {}
