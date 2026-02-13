import { Injectable, Inject } from '@nestjs/common';
import { Resend } from 'resend';
import { ConfigService } from '@nestjs/config';
import { PinoLogger } from 'nestjs-pino';
import { readFileSync } from 'fs';
import { join } from 'path';
import Handlebars from 'handlebars';
import { MailServiceError } from '../common/exceptions/custom-errors';
import { getTemplatesDir } from './mail.config';

@Injectable()
export class MailService {
  private readonly appName: string;
  private readonly appUrl: string;
  private readonly from: string;
  private readonly templatesDir: string;

  constructor(
    @Inject('RESEND_CLIENT') private readonly resend: Resend,
    private readonly configService: ConfigService,
    private readonly logger: PinoLogger,
  ) {
    this.appName = this.configService.get<string>('APP_NAME') || 'Our App';
    this.appUrl = this.configService.get<string>('APP_URL') || 'http://localhost:4200';
    this.from = this.configService.get<string>('RESEND_FROM')!;
    this.templatesDir = getTemplatesDir();
    this.logger.setContext(MailService.name);
  }

  /**
   * Load and compile a handlebars template
   */
  private loadTemplate(templateName: string): (context: any) => string {
    const templatePath = join(this.templatesDir, `${templateName}.hbs`);
    const templateContent = readFileSync(templatePath, 'utf-8');
    return Handlebars.compile(templateContent);
  }

  /**
   * Send email using Resend HTTP API
   */
  private async sendViaResend(to: string, subject: string, html: string): Promise<void> {
    const response = await this.resend.emails.send({
      from: this.from,
      to,
      subject,
      html,
    });

    if (response.error) {
      throw new Error(`Resend API error: ${response.error.message}`);
    }
  }

  async sendEmailVerification(email: string, token: string, userName?: string): Promise<void> {
    try {
      const verificationUrl = `${this.appUrl}/auth/verify-email?token=${token}`;
      const template = this.loadTemplate('verify-email');
      const html = template({
        appName: this.appName,
        userName: userName || email.split('@')[0],
        verificationUrl,
        token,
      });

      await this.sendViaResend(email, `Verify your ${this.appName} account`, html);
    } catch (error) {
      this.logger.error({ error }, 'Failed to send verification email');
      throw new MailServiceError(`Failed to send verification email to ${email}`, {
        code: 'VERIFICATION_EMAIL_FAILED',
        details: {
          email,
          error: error instanceof Error ? error.message : String(error),
        },
      });
    }
  }

  async sendPasswordReset(email: string, token: string, userName?: string): Promise<void> {
    try {
      const resetUrl = `${this.appUrl}/auth/reset-password?token=${token}`;
      const expiryMinutes = this.configService.get<number>('PASSWORD_RESET_EXPIRY_MINUTES') || 60;
      const template = this.loadTemplate('reset-password');
      const html = template({
        appName: this.appName,
        userName: userName || email.split('@')[0],
        resetUrl,
        expiryMinutes,
        token,
      });

      await this.sendViaResend(email, `Reset your ${this.appName} password`, html);
    } catch (error) {
      this.logger.error({ error }, 'Failed to send password reset email');
      throw new MailServiceError(`Failed to send password reset email to ${email}`, {
        code: 'PASSWORD_RESET_EMAIL_FAILED',
        details: {
          email,
          error: error instanceof Error ? error.message : String(error),
        },
      });
    }
  }

  async sendWelcome(email: string, userName?: string): Promise<void> {
    try {
      const template = this.loadTemplate('welcome');
      const html = template({
        appName: this.appName,
        userName: userName || email.split('@')[0],
        loginUrl: `${this.appUrl}/auth/login`,
      });

      await this.sendViaResend(email, `Welcome to ${this.appName}!`, html);
    } catch (error) {
      this.logger.error({ error }, 'Failed to send welcome email');
      throw new MailServiceError(`Failed to send welcome email to ${email}`, {
        code: 'WELCOME_EMAIL_FAILED',
        details: {
          email,
          error: error instanceof Error ? error.message : String(error),
        },
      });
    }
  }
}
