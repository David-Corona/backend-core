import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';
import { mailerConfig } from './mail.config';

@Module({
  imports: [
    MailerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: mailerConfig,
    }),
  ],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}