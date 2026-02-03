import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private readonly appName: string;
  private readonly appUrl: string;

  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {
    this.appName = this.configService.get<string>('APP_NAME') || 'Our App';
    this.appUrl = this.configService.get<string>('APP_URL') || 'http://localhost:3000';
  }

  async sendEmailVerification(email: string, token: string, userName?: string): Promise<void> {
    const verificationUrl = `${this.appUrl}/verify-email?token=${token}`;

    await this.mailerService.sendMail({
      to: email,
      subject: `Verify your ${this.appName} account`,
      template: 'verify-email',
      context: {
        appName: this.appName,
        userName: userName || email.split('@')[0],
        verificationUrl,
        token,
      },
    });
  }

  async sendPasswordReset(email: string, token: string, userName?: string): Promise<void> {
    const resetUrl = `${this.appUrl}/reset-password?token=${token}`;
    const expiryMinutes = this.configService.get<number>('PASSWORD_RESET_EXPIRY_MINUTES') || 60;

    await this.mailerService.sendMail({
      to: email,
      subject: `Reset your ${this.appName} password`,
      template: 'reset-password',
      context: {
        appName: this.appName,
        userName: userName || email.split('@')[0],
        resetUrl,
        expiryMinutes,
        token,
      },
    });
  }

  async sendWelcome(email: string, userName?: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: `Welcome to ${this.appName}!`,
      template: 'welcome',
      context: {
        appName: this.appName,
        userName: userName || email.split('@')[0],
        loginUrl: `${this.appUrl}/login`,
      },
    });
  }
}