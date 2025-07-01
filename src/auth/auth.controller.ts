import { Response, Request } from 'express';
import { LoginDto } from './dto/login-dto';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup-dto';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { Controller, Get, Post, Body, Res } from '@nestjs/common';
import { VerificationLink } from 'src/lib/verificationLink.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private verificationLink: VerificationLink,
  ) {}
  
  @Post('login')
  async login(
    @Body() createAuthDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(createAuthDto, response);
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
