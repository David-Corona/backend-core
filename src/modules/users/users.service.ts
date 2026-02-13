import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ListUsersDto } from './dto/list-users.dto';
import {
  UserAlreadyExistsError,
  UserNotFoundError,
  RoleNotFoundError,
  DefaultRoleNotFoundError,
} from '../../common/exceptions/custom-errors';

@Injectable()
export class UsersService {
  private readonly SALT_ROUNDS = 12;

  constructor(private readonly prisma: PrismaService) {}

  async list(query: ListUsersDto) {
    const { skip = 0, take = 20, email, isActive, isVerified } = query;

    const where: any = {};
    if (email) {
      where.email = { contains: email, mode: 'insensitive' };
    }

    if (typeof isActive === 'boolean') {
      where.isActive = isActive;
    }

    if (typeof isVerified === 'boolean') {
      where.isVerified = isVerified;
    }

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        skip,
        take,
        where,
        include: {
          roles: { 
            include: { role: true },
            orderBy: { role: { name: 'asc' } }
          },
        },
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      data: users,
      meta: {
        total,
        skip,
        take,
        hasMore: skip + take < total,
      },
    };
  }

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: {
        roles: { 
          include: { role: true },
          orderBy: { role: { name: 'asc' } }
        },
      },
    });

    if (!user) {
      throw new UserNotFoundError(`User with ID '${id}' not found`);
    }

    return user;
  }

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        roles: { 
          include: { role: true } 
        },
      },
    });
  }

  async create(dto: CreateUserDto) {
    const normalizedEmail = dto.email.toLowerCase();

    const existing = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      throw new UserAlreadyExistsError(`Email '${normalizedEmail}' is already registered`);
    }

    const hashedPassword = await bcrypt.hash(dto.password, this.SALT_ROUNDS);

    // Validate roles exist
    if (dto.roles && dto.roles.length > 0) {
      const roleNames = dto.roles;
      const existingRoles = await this.prisma.role.findMany({
        where: { name: { in: roleNames } },
      });

      if (existingRoles.length !== roleNames.length) {
        const foundNames = existingRoles.map((r) => r.name);
        const missing = roleNames.filter((name) => !foundNames.includes(name));
        throw new RoleNotFoundError(`Roles not found: ${missing.join(', ')}`);
      }
    } else {
      // Ensure default role exists
      const defaultRole = await this.prisma.role.findUnique({
        where: { name: 'user' },
      });
      if (!defaultRole) {
        throw new DefaultRoleNotFoundError();
      }
    }

    return this.prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        roles: dto.roles
          ? {
              create: dto.roles.map((roleName) => ({
                role: { connect: { name: roleName } },
              })),
            }
          : {
              create: {
                role: { connect: { name: 'user' } }, // Default role
              },
            },
      },
      include: {
        roles: { 
          include: { role: true } 
        },
      },
    });
  }

  async update(id: string, dto: UpdateUserDto) {
    // Ensure user exists
    await this.findById(id);

    const normalizedEmail = dto.email?.toLowerCase();
    if (normalizedEmail) {
      const existing = await this.prisma.user.findUnique({
        where: { email: normalizedEmail },
      });
      if (existing && existing.id !== id) {
        throw new UserAlreadyExistsError(`Email '${normalizedEmail}' is already registered`);
      }
    }

    // Validate roles exist if provided
    if (dto.roles && dto.roles.length > 0) {
      const existingRoles = await this.prisma.role.findMany({
        where: { name: { in: dto.roles } },
      });

      if (existingRoles.length !== dto.roles.length) {
        const foundNames = existingRoles.map((r) => r.name);
        const missing = dto.roles.filter((name) => !foundNames.includes(name));
        throw new RoleNotFoundError(`Roles not found: ${missing.join(', ')}`);
      }
    }

    return this.prisma.$transaction(async (tx) => {
      // Update roles if provided
      if (dto.roles) {
        // Delete existing role assignments
        await tx.userRole.deleteMany({
          where: { userId: id },
        });

        // Get role IDs
        const roles = await tx.role.findMany({
          where: { name: { in: dto.roles } },
        });

        // Create new role assignments
        await tx.userRole.createMany({
          data: roles.map((role) => ({
            userId: id,
            roleId: role.id,
          })),
        });
      }

      return tx.user.update({
        where: { id },
        data: {
          email: normalizedEmail,
          isActive: dto.isActive,
          isVerified: dto.isVerified,
        },
        include: {
          roles: { 
            include: { role: true } 
          },
        },
      });
    });
  }

  async deactivate(id: string) {
    await this.findById(id);

    return this.prisma.user.update({
      where: { id },
      data: { isActive: false },
    });
  }

  async delete(id: string) {
    await this.findById(id);

    return this.prisma.user.delete({
      where: { id },
    });
  }

  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }
}