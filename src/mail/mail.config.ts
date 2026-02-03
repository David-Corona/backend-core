import { MailerOptions } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';

export const mailerConfig = (configService: ConfigService): MailerOptions => ({
  transport: {
    host: 'smtp.resend.com',
    port: 587,
    secure: false, // = Use STARTTLS
    auth: {
      user: 'resend',
      pass: configService.get<string>('RESEND_API_KEY'),
    },
  },
  defaults: {
    from: configService.get<string>('RESEND_FROM') || 'noreply@example.com',
  },
  template: {
    dir: join(__dirname, '..', 'templates', 'emails'),
    adapter: new HandlebarsAdapter(),
    options: {
      strict: true,
    },
  },
});