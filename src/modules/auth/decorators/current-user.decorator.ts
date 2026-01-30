import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Get current user from request
 * Usage: @CurrentUser() user: UserPayload
 */
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);