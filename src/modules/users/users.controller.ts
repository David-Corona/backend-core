import { Controller, Post, Body, Get, Param, Query, Patch, Delete, HttpCode, HttpStatus } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserMapper } from './mappers/user.mapper';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ListUsersDto } from './dto/list-users.dto';
import { UserResponseDto, UserListResponseDto } from './dto/user-response.dto';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('users')
export class UsersController {
  
  constructor(
    private readonly usersService: UsersService,
    private readonly userMapper: UserMapper,
  ) {}

  @Roles('admin')
  @Get()
  async list(@Query() query: ListUsersDto): Promise<UserListResponseDto> {
    const result = await this.usersService.list(query);
    
    return {
      data: this.userMapper.toResponseDtoArray(result.data),
      meta: result.meta,
    };
  }

  @Roles('admin')
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<UserResponseDto> {
    const user = await this.usersService.findById(id);
    return this.userMapper.toResponseDto(user);
  }

  @Roles('admin')
  @Post()
  async create(@Body() dto: CreateUserDto): Promise<UserResponseDto> {
    const user = await this.usersService.create(dto);
    return this.userMapper.toResponseDto(user);
  }

  @Roles('admin')
  @Patch(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateUserDto): Promise<UserResponseDto> {
    const user = await this.usersService.update(id, dto);
    return this.userMapper.toResponseDto(user);
  }

  @Roles('admin')
  @Delete(':id/deactivate')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deactivate(@Param('id') id: string): Promise<void> {
    await this.usersService.deactivate(id);
  }

  @Roles('admin')
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    await this.usersService.delete(id);
  }
}