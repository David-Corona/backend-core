import { Injectable } from '@nestjs/common';
import { UserResponseDto, RoleDto } from '../dto/user-response.dto';
import { Role, User } from '../../../generated/prisma/client';

type UserWithRoles = User & {
  roles: Array<{ role: Role }>;
};

@Injectable()
export class UserMapper {
  /**
   * Map Prisma User to response DTO
   */
  toResponseDto(user: UserWithRoles): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      isVerified: user.isVerified,
      isActive: user.isActive,
      roles: user.roles.map((ur) => this.toRoleDto(ur.role)),
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  toResponseDtoArray(users: UserWithRoles[]): UserResponseDto[] {
    return users.map((user) => this.toResponseDto(user));
  }

  private toRoleDto(role: Role): RoleDto {
    return {
      id: role.id,
      name: role.name,
    };
  }
}