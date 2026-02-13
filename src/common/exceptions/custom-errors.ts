import { HttpException, HttpStatus, BadRequestException, UnauthorizedException, ForbiddenException,
  NotFoundException, ConflictException } from '@nestjs/common';

export interface ErrorContext {
  code?: string;
  details?: any;
}

/**
 * Token expired error (triggers refresh attempt)
 */
export class TokenExpiredError extends UnauthorizedException {
  constructor(message: string = 'Access token has expired', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'TOKEN_EXPIRED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Token refresh failed error
 */
export class TokenRefreshError extends UnauthorizedException {
  constructor(message: string = 'Failed to refresh access token', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'TOKEN_REFRESH_FAILED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Invalid credentials error
 */
export class InvalidCredentialsError extends UnauthorizedException {
  constructor(message: string = 'Invalid email or password', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'INVALID_CREDENTIALS',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * User already exists error
 */
export class UserAlreadyExistsError extends ConflictException {
  constructor(message: string = 'User already exists', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'USER_ALREADY_EXISTS',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * User not found error
 */
export class UserNotFoundError extends NotFoundException {
  constructor(message: string = 'User not found', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'USER_NOT_FOUND',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Email verification token expired
 */
export class VerificationTokenExpiredError extends BadRequestException {
  constructor(message: string = 'Verification token has expired', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'VERIFICATION_TOKEN_EXPIRED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Invalid verification token
 */
export class InvalidVerificationTokenError extends BadRequestException {
  constructor(message: string = 'Invalid verification token', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'INVALID_VERIFICATION_TOKEN',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Email already verified
 */
export class EmailAlreadyVerifiedError extends BadRequestException {
  constructor(message: string = 'Email is already verified', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'EMAIL_ALREADY_VERIFIED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Email not verified
 */
export class EmailNotVerifiedError extends ForbiddenException {
  constructor(message: string = 'Email is not verified', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'EMAIL_NOT_VERIFIED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Mail service error
 */
export class MailServiceError extends HttpException {
  constructor(message: string = 'Failed to send email', context?: ErrorContext) {
    super(
      {
        message,
        code: context?.code || 'MAIL_SERVICE_ERROR',
        ...(context?.details && { details: context.details }),
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}

/**
 * Account deactivated error
 */
export class AccountDeactivatedException extends ForbiddenException {
  constructor(message: string = 'Your account has been deactivated', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'ACCOUNT_DEACTIVATED',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Default role not found error
 */
export class DefaultRoleNotFoundError extends HttpException {
  constructor(message: string = 'Default user role not found. Please run database seed.', context?: ErrorContext) {
    super(
      {
        message,
        code: context?.code || 'DEFAULT_ROLE_NOT_FOUND',
        ...(context?.details && { details: context.details }),
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}

/**
 * Role not found error
 */
export class RoleNotFoundError extends BadRequestException {
  constructor(message: string = 'One or more roles not found', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'ROLE_NOT_FOUND',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * Session not found error
 */
export class SessionNotFoundError extends BadRequestException {
  constructor(message: string = 'Session not found', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'SESSION_NOT_FOUND',
      ...(context?.details && { details: context.details }),
    });
  }
}

/**
 * User inactive error
 */
export class UserInactiveError extends UnauthorizedException {
  constructor(message: string = 'User account is inactive', context?: ErrorContext) {
    super({
      message,
      code: context?.code || 'USER_INACTIVE',
      ...(context?.details && { details: context.details }),
    });
  }
}
