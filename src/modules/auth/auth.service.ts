import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { PinoLogger } from 'nestjs-pino';
import { PrismaService } from '../../prisma/prisma.service';
import { RegisterDto, LoginDto } from './dto/auth.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { SessionDto } from './dto/auth-response.dto';
import { MailService } from '../../mail/mail.service';
import { VerificationToken } from '../../generated/prisma/client';
import {
  UserAlreadyExistsError,
  DefaultRoleNotFoundError,
  InvalidVerificationTokenError,
  EmailAlreadyVerifiedError,
  InvalidCredentialsError,
  AccountDeactivatedException,
  EmailNotVerifiedError,
  TokenRefreshError,
  SessionNotFoundError,
  UserInactiveError,
  UserNotFoundError,
} from '../../common/exceptions/custom-errors';

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS: number;
  private readonly ACCESS_TOKEN_EXPIRY: number;
  private readonly REFRESH_TOKEN_EXPIRY_MS: number;
  private readonly VERIFICATION_TOKEN_EXPIRY_MS: number;
  private readonly PASSWORD_RESET_EXPIRY_MS: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(AuthService.name);
    this.SALT_ROUNDS = this.configService.get<number>('BCRYPT_SALT_ROUNDS', { infer: true })!;

    const accessExpiryInMinutes = this.configService.get<number>('JWT_ACCESS_EXPIRY_MINUTES', { infer: true })!;
    this.ACCESS_TOKEN_EXPIRY = accessExpiryInMinutes * 60;
    const refreshDays = this.configService.get<number>('JWT_REFRESH_EXPIRY_DAYS', { infer: true })!;
    this.REFRESH_TOKEN_EXPIRY_MS = refreshDays * 24 * 60 * 60 * 1000;

    const verificationHours = this.configService.get<number>('EMAIL_VERIFICATION_EXPIRY_HOURS', { infer: true }) || 24;
    this.VERIFICATION_TOKEN_EXPIRY_MS = verificationHours * 60 * 60 * 1000;

    const resetMinutes = this.configService.get<number>('PASSWORD_RESET_EXPIRY_MINUTES', { infer: true }) || 60;
    this.PASSWORD_RESET_EXPIRY_MS = resetMinutes * 60 * 1000;
  }

  async register(dto: RegisterDto): Promise<{ user: any; tokens: { accessToken: string; refreshToken: string } }> {
    const normalizedEmail = dto.email.toLowerCase();

    const existing = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      throw new UserAlreadyExistsError(`Email '${normalizedEmail}' is already registered`);
    }

    const hashedPassword = await bcrypt.hash(dto.password, this.SALT_ROUNDS);

    const userRole = await this.prisma.role.findUnique({
      where: { name: 'user' },
    });
    if (!userRole) {
      throw new DefaultRoleNotFoundError();
    }

    const user = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        isVerified: false,
        isActive: true,
        roles: {
          create: [{ roleId: userRole.id }],
        },
      },
      include: {
        roles: {
          include: { role: true },
        },
      },
    });

    await this.sendVerificationEmail(user.id, user.email).catch((err) => {
      // Not throwing error. Registration succeeded, user can request new verification email
      this.logger.error({ err }, 'Failed to send verification email');
    });

    return this.buildAuthResponse(user, {});
  }

  async sendVerificationEmail(userId: string, email: string): Promise<void> {
    // Invalidate any existing verification tokens for this user
    await this.prisma.verificationToken.updateMany({
      where: {
        userId,
        type: 'email_verification',
        usedAt: null,
      },
      data: {
        usedAt: new Date(), // Mark as used to prevent reuse
      },
    });

    const token = this.generateSecureToken(userId);
    const hashedToken = await bcrypt.hash(token, 10);

    await this.prisma.verificationToken.create({
      data: {
        token: hashedToken,
        type: 'email_verification',
        userId,
        expiresAt: new Date(Date.now() + this.VERIFICATION_TOKEN_EXPIRY_MS),
      },
    });

    await this.mailService.sendEmailVerification(email, token); // TODO - Add name
  }

  async verifyEmail(token: string): Promise<void> {
    const parts = token.split('.');
    if (parts.length !== 2) {
      throw new InvalidVerificationTokenError();
    }
    const [userId, tokenValue] = parts;

    const dbToken = await this.prisma.verificationToken.findFirst({
      where: {
        userId,
        type: 'email_verification',
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    });
    if (!dbToken) {
      throw new InvalidVerificationTokenError();
    }

    // Check token
    const isMatch = await bcrypt.compare(token, dbToken?.token);
    if (!isMatch) {
      throw new InvalidVerificationTokenError();
    }

    // Check if already verified
    if (dbToken.user.isVerified) {
      throw new EmailAlreadyVerifiedError();
    }

    // Mark token as used and user as verified
    await this.prisma.$transaction([
      this.prisma.verificationToken.update({
        where: { id: dbToken.id },
        data: { usedAt: new Date() },
      }),
      this.prisma.user.update({
        where: { id: dbToken.userId },
        data: { isVerified: true },
      }),
    ]);

    // Send welcome email
    await this.mailService.sendWelcome(dbToken.user.email); // TODO - Add name
  }

  async resendVerification(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      return; // Don't reveal if email exists
    }

    if (user.isVerified) {
      throw new EmailAlreadyVerifiedError();
    }

    await this.sendVerificationEmail(user.id, user.email);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      return; // Don't reveal if email exists
    }

    // Invalidate existing reset tokens
    await this.prisma.verificationToken.updateMany({
      where: {
        userId: user.id,
        type: 'password_reset',
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });

    const token = this.generateSecureToken(user.id);
    const hashedToken = await bcrypt.hash(token, 10);

    await this.prisma.verificationToken.create({
      data: {
        token: hashedToken,
        type: 'password_reset',
        userId: user.id,
        expiresAt: new Date(Date.now() + this.PASSWORD_RESET_EXPIRY_MS),
      },
    });

    await this.mailService.sendPasswordReset(user.email, token); // TODO - Add name
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const parts = token.split('.');
    if (parts.length !== 2) {
      throw new InvalidVerificationTokenError('Invalid or expired password reset token');
    }
    const [userId, tokenValue] = parts;

    const dbToken = await this.prisma.verificationToken.findFirst({
      where: {
        userId,
        type: 'password_reset',
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    });
    if (!dbToken) {
      throw new InvalidVerificationTokenError('Invalid or expired password reset token');
    }

    const isMatch = await bcrypt.compare(token, dbToken.token);
    if (!isMatch) {
      throw new InvalidVerificationTokenError('Invalid or expired password reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, this.SALT_ROUNDS);

    await this.prisma.$transaction([
      this.prisma.verificationToken.update({
        where: { id: dbToken.id },
        data: { usedAt: new Date() },
      }),
      this.prisma.user.update({
        where: { id: dbToken.userId },
        data: { password: hashedPassword },
      }),
      this.prisma.refreshToken.updateMany({
        where: { userId: dbToken.userId },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
          revokedBy: 'password_reset',
        },
      }),
    ]);
  }

  async login(
    dto: LoginDto,
    metadata: {
      userAgent?: string;
      ipAddress?: string;
      deviceId?: string;
      deviceName?: string;
    },
  ): Promise<{ user: any; tokens: { accessToken: string; refreshToken: string } }> {
    const normalizedEmail = dto.email.toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
      include: {
        roles: {
          include: { role: true },
        },
      },
    });
    // Added dummy hash to prevent timing attacks when user is not found
    const passwordToCheck = user?.password ?? '$2b$10$dummy.hash.that.will.never.match.anything';
    const isPasswordValid = await bcrypt.compare(dto.password, passwordToCheck);
    if (!user || !isPasswordValid) {
      throw new InvalidCredentialsError();
    }

    if (!user.isActive) {
      throw new AccountDeactivatedException();
    }

    if (!user.isVerified) {
      throw new EmailNotVerifiedError('Please verify your email before logging in');
    }

    return this.buildAuthResponse(user, metadata);
  }

  /**
   * Refresh access token (refresh token from cookie)
   */
  async refresh(
    refreshToken: string,
    metadata: {
      userAgent?: string;
      ipAddress?: string;
    },
  ): Promise<{ user: any; tokens: { accessToken: string; refreshToken: string } }> {
    const hashedToken = this.hashToken(refreshToken);

    // Use transaction to prevent race conditions
    const result = await this.prisma.$transaction(async (tx) => {
      const storedToken = await tx.refreshToken.findUnique({
        where: { token: hashedToken },
        include: {
          user: {
            include: {
              roles: {
                include: { role: true },
              },
            },
          },
        },
      });

      if (!storedToken) {
        throw new TokenRefreshError('Invalid refresh token');
      }
      if (storedToken.isRevoked) {
        throw new TokenRefreshError('Refresh token has been revoked');
      }
      if (new Date() > storedToken.expiresAt) {
        throw new TokenRefreshError('Refresh token has expired');
      }

      // Revoke old token (token rotation)
      await tx.refreshToken.update({
        where: { id: storedToken.id },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
          revokedBy: 'token_rotation',
        },
      });

      // Return user data to create new tokens
      return storedToken;
    });
    
    // Create new tokens with same device info
    return this.buildAuthResponse(result.user, {
      userAgent: metadata.userAgent || result.userAgent,
      ipAddress: metadata.ipAddress || result.ipAddress,
      deviceId: result.deviceId || undefined,
      deviceName: result.deviceName || undefined,
    });
  }

  /**
   * Logout current session
   */
  async logout(refreshToken: string): Promise<void> {
    const hashedToken = this.hashToken(refreshToken);

    await this.prisma.refreshToken.updateMany({
      where: { token: hashedToken },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedBy: 'user',
      },
    });
  }

  /**
   * Logout all sessions for a user
   */
  async logoutAll(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedBy: 'user',
      },
    });
  }

  /**
   * Logout all sessions except current
   */
  async logoutOthers(userId: string, currentRefreshToken: string): Promise<void> {
    const hashedToken = this.hashToken(currentRefreshToken);

    const currentToken = await this.prisma.refreshToken.findUnique({
      where: { token: hashedToken },
    });
    if (!currentToken) {
      throw new TokenRefreshError('Invalid refresh token');
    }

    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        id: { not: currentToken.id },
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedBy: 'user',
      },
    });
  }

  /**
   * Get all active sessions for a user
   */
  async getSessions(userId: string, currentRefreshToken?: string): Promise<SessionDto[]> {
    const sessions = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastUsedAt: 'desc' },
    });

    let currentTokenHash: string | undefined;
    if (currentRefreshToken) {
      currentTokenHash = this.hashToken(currentRefreshToken);
    }

    return sessions.map((session) => ({
      id: session.id,
      deviceId: session.deviceId || undefined,
      deviceName: session.deviceName || undefined,
      ipAddress: session.ipAddress,
      lastUsedAt: session.lastUsedAt,
      createdAt: session.createdAt,
      isCurrent: session.token === currentTokenHash,
    }));
  }

  /**
   * Revoke specific session
   */
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    const session = await this.prisma.refreshToken.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });
    if (!session) {
      throw new SessionNotFoundError();
    }

    await this.prisma.refreshToken.update({
      where: { id: sessionId },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedBy: 'user',
      },
    });
  }

  /**
   * Validate user from JWT payload
   */
  async validateUser(payload: JwtPayload) {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: {
        roles: {
          include: { role: true },
        },
      },
    });

    if (!user) {
      throw new UserNotFoundError('User not found');
    }

    if (!user.isActive) {
      throw new UserInactiveError();
    }

    return user;
  }

  private async buildAuthResponse(
    user: any, // TODO
    metadata: {
      userAgent?: string;
      ipAddress?: string;
      deviceId?: string;
      deviceName?: string;
    },
  ): Promise<{ user: any; tokens: { accessToken: string; refreshToken: string } }> {
    const roleNames = user.roles.map((ur: any) => ur.role.name);

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: roleNames,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.ACCESS_TOKEN_EXPIRY,
    });

    const refreshToken = this.generateRefreshToken();
    const hashedRefreshToken = this.hashToken(refreshToken);

    await this.prisma.refreshToken.create({
      data: {
        token: hashedRefreshToken,
        userId: user.id,
        userAgent: metadata.userAgent || 'unknown',
        ipAddress: metadata.ipAddress || 'unknown',
        deviceId: metadata.deviceId,
        deviceName: metadata.deviceName,
        expiresAt: new Date(Date.now() + this.REFRESH_TOKEN_EXPIRY_MS),
      },
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        isVerified: user.isVerified,
        roles: roleNames,
      },
      tokens: {
        accessToken,
        refreshToken,
      },
    };
  }

  private generateRefreshToken(): string {
    return randomBytes(64).toString('hex');
  }

  private generateSecureToken(userId: string): string {
    const random = randomBytes(32).toString('hex');
    return `${userId}.${random}`
  }

  private hashToken(token: string): string {
    return bcrypt.hashSync(token, 10);
  }

  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    return result.count;
  }

  async cleanupExpiredVerificationTokens(): Promise<number> {
    const result = await this.prisma.verificationToken.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    return result.count;
  }
}
