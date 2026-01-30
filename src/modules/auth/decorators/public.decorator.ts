import { SetMetadata } from '@nestjs/common';

/**
 * Mark route as public
 * Usage: @Public()
 */
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);