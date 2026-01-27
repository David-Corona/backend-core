import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { UserMapper } from './mappers/user.mapper';

@Module({
  providers: [UsersService, UserMapper],
  controllers: [UsersController],
  exports: [UsersService, UserMapper],
})
export class UsersModule {}