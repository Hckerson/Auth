import { Req } from '@nestjs/common';
import { LoginDto } from './dto/login-dto';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup-dto';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { Controller, Get, Post, Body, Res } from '@nestjs/common';
import { RiskAssesmentService } from 'src/lib/risk-assesment.service';
import { VerificationLink } from 'src/lib/verificationLink.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly verificationLink: VerificationLink,
    private readonly riskAssesmentService: RiskAssesmentService,
  ) {}

  private getIpAddress(request: Request) {
    // generates ip address and checks for proxy
    let ip =
      (request.headers['x-forwarded-for'] as string) ||
      request.socket.remoteAddress ||
      null;

    if (!ip) return;
    if (ip.includes(',')) {
      ip = ip.split(',')[0];
    }

    if (ip === '::1') {
      ip = '127.0.0.1';
    }
    if (ip.startsWith('::ffff:')) {
      ip = ip.substring(7);
    }
    return ip;
  }

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
  ) {
    if (!loginDto) return `No loginDto passed`
    const ipAddress = this.getIpAddress(request);
    const updatedLoginDto = { ...loginDto, ipAddress };
    try {
      const threatLevel = await this.riskAssesmentService.getThreatLevel(
        updatedLoginDto,
        request,
      );

      return this.authService.login(updatedLoginDto, response, threatLevel);
    } catch (error) {
      console.error(`Error accesing threat level`);
    }
  }

  @Post('signup')
  async signup(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @Post('send-reset-password-link')
  async sendResetPasswordLink(@Body() email: string) {
    const verificationLink =
      await this.verificationLink.generateVerificationLink(email);
    return this.authService.sendResetPasswordLink(email, verificationLink);
  }

  @Post('verify-email')
  async verifyEmail(@Body() email: string) {
    const verificationLink =
      await this.verificationLink.generateVerificationLink(email);
    return this.authService.verifyEmail(email, verificationLink);
  }

  @Get('logout')
  logout(@Res({ passthrough: true }) response: Response) {
    return this.authService.logout(response);
  }
}
