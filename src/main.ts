import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino'
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';


async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const configService = app.get(ConfigService);

  app.useLogger(app.get(Logger));
  app.use(cookieParser());

  // Configure CORS
  const corsOrigins = configService
    .get<string>('CORS_ORIGINS', { infer: true })
    ?.split(',')
    .map((origin) => origin.trim()) || ['http://localhost:4200'];

  app.enableCors({
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  app.setGlobalPrefix('api');
  app.enableShutdownHooks();

  // Global Pipes - Validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip properties without decorators
      forbidNonWhitelisted: true, // Throw error if non-whitelisted properties exist
      transform: true, // Transform payloads to DTO instances
      transformOptions: {
        enableImplicitConversion: true,
      },
      // disableErrorMessages: process.env.NODE_ENV === 'production', // Hide details in prod
      // Return detailed validation errors
      // validationError: {
      //   target: process.env.NODE_ENV !== 'production',
      //   value: process.env.NODE_ENV !== 'production',
      // },
    })
  );

  const port = configService.get<number>('PORT', { infer: true }) ?? 3000;
  await app.listen(port);

}
bootstrap();
