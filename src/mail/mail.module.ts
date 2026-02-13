import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';
import { createResendClient } from './mail.config';

@Module({
  providers: [
    MailService,
    {
      provide: 'RESEND_CLIENT',
      useFactory: (configService: ConfigService) => createResendClient(configService),
      inject: [ConfigService],
    },
  ],
  exports: [MailService],
})
export class MailModule {}