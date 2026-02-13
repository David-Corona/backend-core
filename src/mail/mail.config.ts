import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import { join } from 'path';
import { existsSync } from 'fs';

export function getTemplatesDir(): string {
  // Determine the correct template directory
  // In production: dist/src/templates/emails
  // In development: src/templates/emails
  let templatesDir = join(__dirname, '..', 'templates', 'emails');

  // Fallback for development environment
  if (!existsSync(templatesDir)) {
    templatesDir = join(process.cwd(), 'src', 'templates', 'emails');
  }

  return templatesDir;
}

export function createResendClient(configService: ConfigService): Resend {
  const apiKey = configService.get<string>('RESEND_API_KEY');
  if (!apiKey) {
    throw new Error('RESEND_API_KEY is not defined in environment variables');
  }
  return new Resend(apiKey);
}