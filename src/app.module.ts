import { Module } from '@nestjs/common';
import { CoreModule } from './core/core.module';
import { HealthModule } from './health/health.module';
import { UsersModule } from './modules/users/users.module';

@Module({
  imports: [
    CoreModule,
    HealthModule,
    UsersModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
