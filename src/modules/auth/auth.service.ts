import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { RegisterDto, LoginDto } from './dto/auth.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { SessionDto } from './dto/auth-response.dto';

@Injectable()
export class AuthService {

  private readonly SALT_ROUNDS: number;
  private readonly ACCESS_TOKEN_EXPIRY: number;
  private readonly REFRESH_TOKEN_EXPIRY_MS: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.SALT_ROUNDS = this.configService.get<number>('BCRYPT_SALT_ROUNDS', { infer: true })!;
    const accessExpiryInMinutes = this.configService.get<number>('JWT_ACCESS_EXPIRY_MINUTES', { infer: true })!;
    this.ACCESS_TOKEN_EXPIRY = accessExpiryInMinutes * 60;
    const refreshDays = this.configService.get<number>('JWT_REFRESH_EXPIRY_DAYS', { infer: true })!;
    this.REFRESH_TOKEN_EXPIRY_MS = refreshDays * 24 * 60 * 60 * 1000;
  }

  async register(dto: RegisterDto): Promise<{ user: any; tokens: { accessToken: string; refreshToken: string } }> {
    const normalizedEmail = dto.email.toLowerCase();

    const existing = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, this.SALT_ROUNDS);

    const userRole = await this.prisma.role.findUnique({
      where: { name: 'user' },
    });
    if (!userRole) {
      throw new BadRequestException('Default user role not found. Please run database seed.');
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

    return this.buildAuthResponse(user, {});
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
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(dto.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
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

    const storedToken = await this.prisma.refreshToken.findUnique({
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
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (storedToken.isRevoked) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }
    if (new Date() > storedToken.expiresAt) {
      throw new UnauthorizedException('Refresh token has expired');
    }

    // Revoke old token (token rotation)
    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
        revokedBy: 'token_rotation',
      },
    });

    // Create new tokens with same device info
    return this.buildAuthResponse(storedToken.user, {
      userAgent: metadata.userAgent || storedToken.userAgent,
      ipAddress: metadata.ipAddress || storedToken.ipAddress,
      deviceId: storedToken.deviceId || undefined,
      deviceName: storedToken.deviceName || undefined,
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
      throw new UnauthorizedException('Invalid refresh token');
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
      throw new BadRequestException('Session not found');
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

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or inactive');
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
}
