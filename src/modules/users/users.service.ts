import { Injectable, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateUserDto, UserResponseDto } from './users.dto';
import * as bcrypt from 'bcrypt';


@Injectable()
export class UsersService {

  constructor(private readonly prisma: PrismaService) {}

  async create(dto: CreateUserDto): Promise<UserResponseDto> {
    const hashedPassword = await bcrypt.hash(dto.password, 10);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
        },
      });

      return this.toResponse(user);
    } catch (err: any) {
      // Prisma unique constraint
      if (err.code === 'P2002') {
        throw new ConflictException('Email already in use');
      }
      throw err;
    }
  }

  async findById(id: string): Promise<UserResponseDto | null> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    return user ? this.toResponse(user) : null;
  }

  // async findByEmail(email: string) {
  //   return this.prisma.user.findUnique({ where: { email } });
  //   // This returns password → only for AuthModule
  // }

  private toResponse(user: any): UserResponseDto {
    const { password, ...rest } = user;
    return rest;
  }
}
