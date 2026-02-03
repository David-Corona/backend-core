import { Injectable } from '@nestjs/common';
// import { Cron } from '@nestjs/schedule';
import { PinoLogger } from 'nestjs-pino';
import { AuthService } from '../modules/auth/auth.service';

@Injectable()
export class SchedulerService {
  constructor(
    private readonly logger: PinoLogger,
    private readonly authService: AuthService,
  ) {
    this.logger.setContext(SchedulerService.name);
  }

  // Runs daily at 2 AM
  // @Cron('0 2 * * *')
  async cleanupExpiredRefreshTokens(): Promise<void> {
    this.logger.info('Running cleanup: Expired refresh tokens');

    try {
      const count = await this.authService.cleanupExpiredTokens();
      this.logger.info({ count }, 'Cleaned up expired refresh tokens');
    } catch (error) {
      this.logger.error({ err: error }, 'Failed to cleanup expired refresh tokens');
    }
  }

  // Runs daily at 3 AM
  // @Cron('0 3 * * *')
  async cleanupExpiredVerificationTokens(): Promise<void> {
    this.logger.info( 'Running cleanup: Expired verification tokens');

    try {
      const count =
        await this.authService.cleanupExpiredVerificationTokens();
      this.logger.info({ count }, 'Cleaned up expired verification tokens',);
    } catch (error) {
      this.logger.error({ err: error }, 'Failed to cleanup expired verification tokens');
    }
  }
}
