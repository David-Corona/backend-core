export class RoleDto {
  id: string;
  name: string;
}

export class UserResponseDto {
  id: string;
  email: string;
  isVerified: boolean;
  isActive: boolean;
  roles: RoleDto[];
  createdAt: Date;
  updatedAt: Date;
}

export class UserListResponseDto {
  data: UserResponseDto[];
  meta: {
    total: number;
    skip: number;
    take: number;
    hasMore: boolean;
  };
}