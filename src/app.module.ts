import { Module } from '@nestjs/common';
import { CoreModule } from './core/core.module';
import { HealthModule } from './health/health.module';

@Module({
  imports: [
    CoreModule,
    HealthModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
