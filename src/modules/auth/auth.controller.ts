import { Controller, Post, Body, Get, Delete, Param, HttpCode, HttpStatus, Req, Res, UnauthorizedException} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dto/auth.dto';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { AuthResponseDto, SessionDto } from './dto/auth-response.dto';
import { RequestPasswordResetDto, ResendVerificationDto, ResetPasswordDto, VerifyEmailDto } from './dto/verification.dto';


interface UserPayload {
  id: string;
  email: string;
  roles: string[];
}

@Controller('auth')
export class AuthController {

  private readonly REFRESH_TOKEN_COOKIE = 'refreshToken';
  private readonly COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict' as const,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/',
  };

  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response): Promise<AuthResponseDto> {
    const result = await this.authService.register(dto);

    // Set refresh token as HttpOnly cookie
    res.cookie(this.REFRESH_TOKEN_COOKIE, result.tokens.refreshToken, this.COOKIE_OPTIONS);

    return {
      user: result.user,
      accessToken: result.tokens.accessToken,
    };
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const metadata = {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
      deviceId: req.headers['x-device-id'] as string | undefined,
      deviceName: req.headers['x-device-name'] as string | undefined,
    };

    const result = await this.authService.login(dto, metadata);

    // Set refresh token as HttpOnly cookie
    res.cookie(this.REFRESH_TOKEN_COOKIE, result.tokens.refreshToken, this.COOKIE_OPTIONS);

    return {
      user: result.user,
      accessToken: result.tokens.accessToken,
    };
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<AuthResponseDto> {
    const refreshToken = req.cookies[this.REFRESH_TOKEN_COOKIE];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const metadata = {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
    };

    const result = await this.authService.refresh(refreshToken, metadata);

    res.cookie(this.REFRESH_TOKEN_COOKIE, result.tokens.refreshToken, this.COOKIE_OPTIONS);

    return {
      user: result.user,
      accessToken: result.tokens.accessToken,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<void> {
    const refreshToken = req.cookies[this.REFRESH_TOKEN_COOKIE];

    if (refreshToken) {
      await this.authService.logout(refreshToken);
    }

    res.clearCookie(this.REFRESH_TOKEN_COOKIE, { path: '/' });
  }

  @Post('logout/all')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutAll(@CurrentUser() user: UserPayload, @Res({ passthrough: true }) res: Response): Promise<void> {
    await this.authService.logoutAll(user.id);

    res.clearCookie(this.REFRESH_TOKEN_COOKIE, { path: '/' });
  }

  @Post('logout/others')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutOthers(@CurrentUser() user: UserPayload, @Req() req: Request): Promise<void> {
    const refreshToken = req.cookies[this.REFRESH_TOKEN_COOKIE];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    await this.authService.logoutOthers(user.id, refreshToken);
  }

  @Get('sessions')
  async getSessions(@CurrentUser() user: UserPayload, @Req() req: Request): Promise<{ sessions: SessionDto[] }> {
    const currentRefreshToken = req.cookies[this.REFRESH_TOKEN_COOKIE];
    const sessions = await this.authService.getSessions(user.id, currentRefreshToken);
    return { sessions };
  }

  @Delete('sessions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSession(@CurrentUser() user: UserPayload, @Param('id') sessionId: string): Promise<void> {
    await this.authService.revokeSession(user.id, sessionId);
  }

  @Get('me')
  async getMe(@CurrentUser() user: UserPayload) {
    return user;
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() dto: VerifyEmailDto): Promise<{ message: string }> {
    await this.authService.verifyEmail(dto.token);
    return { message: 'Email verified successfully' };
  }

  @Public()
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Body() dto: ResendVerificationDto): Promise<{ message: string }> {
    await this.authService.resendVerification(dto.email);
    return { message: 'If the email exists, a verification link has been sent' };
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() dto: RequestPasswordResetDto): Promise<{ message: string }> {
    await this.authService.requestPasswordReset(dto.email);
    return { message: 'If the email exists, a password reset link has been sent' };
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<{ message: string }> {
    await this.authService.resetPassword(dto.token, dto.newPassword);
    return { message: 'Password reset successfully. Please log in with your new password.' };
  }
}
