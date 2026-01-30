import { SetMetadata } from '@nestjs/common';

/**
 * Require specific roles
 * Usage: @Roles('admin', 'moderator')
 */
export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);