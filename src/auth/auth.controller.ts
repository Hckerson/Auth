import { LoginDto } from './dto/login-dto';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup-dto';
import { Param, Req, UseGuards } from '@nestjs/common';
import { SpeakeasyService } from 'src/lib/speakesy.service';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { Controller, Get, Post, Body, Res } from '@nestjs/common';
import { VerificationLink } from 'src/lib/verificationLink.service';
import { RiskAssesmentService } from 'src/lib/risk-assesment.service';
import { LocalAuthGuard } from './service/passport/guards/local-auth.guard';
import { GithubAuthGuard } from './service/passport/guards/github-auth.guard';
import { GoogleAuthGuard } from './service/passport/guards/google-auth.guard';
import { GithubStrategy } from './service/passport/strategies/github.strategy';
import { GoogleStrategy } from './service/passport/strategies/google.strategy';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly githubStrategy: GithubStrategy,
    private readonly googleStrategy: GoogleStrategy,
    private readonly verificationLink: VerificationLink,
    private readonly speakeasyService: SpeakeasyService,
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

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
  ) {
    if (!loginDto) return `No loginDto passed`;
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
  async signup(@Body() signUpDto: SignUpDto, @Req() request: Request) {
    const ipAddress = this.getIpAddress(request) || '';
    return this.authService.signUp(signUpDto, ipAddress, request);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @Post('send-reset-password-link')
  async sendResetPasswordLink(@Body('email') email: string) {
    const verificationLink =
      await this.verificationLink.generateVerificationLink(email);
    console.log(`Verification link: ${verificationLink}`);
    return await this.authService.sendResetPasswordLink(
      email,
      verificationLink,
    );
  }

  @Post('2fa/setup')
  async setup2fa(@Req() request: Request) {
    const user = request.cookies['sessionToken'];
    const userData = await this.authService.decrypt(user);
    if (!userData) return;
    const { id } = userData.payload;
    const otpauthUrl = await this.speakeasyService.setupTwoFactor(id as string);
    const qrCode = await this.speakeasyService.getQrCodeForUser(id as string);
    return { otpauthUrl, qrCode };
  }

  @UseGuards(GithubAuthGuard)
  @Get('login/github')
  async githubLogin(@Req() request: Request) {
    return '';
  }
  @UseGuards(GithubAuthGuard)
  @Get('callback/github')
  async githubCallback(@Req() request: Request, @Res() response: Response) {
    if (!request.user)
      return response.redirect(this.githubStrategy.failureRedirect);
    return response.redirect(this.githubStrategy.successRedirect);
  }

  @UseGuards(GoogleAuthGuard)
  @Get('login/google')
  async GoogleLogin(@Req() request: Request) {
    return '';
  }

  @UseGuards(GoogleAuthGuard)
  @Get('callback/google')
  async GoogleCallback(@Req() request: Request, @Res() response: Response) {
    if (!request.user)
      return response.redirect(this.googleStrategy.failureRedirect);
    return response.redirect(this.googleStrategy.successRedirect);
  }

  @Get('successRedirect/:email')
  async test(
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
    @Param('email') email: string,
  ) {
    try {
      const ipAddress = this.getIpAddress(request) || '';
      return this.authService.success(response, email);
    } catch (error) {
      console.log(`Error redirecting to success route`);
    }
  }

  @Get('failureRedirect')
  async fail() {
    return 'failed';
  }

  @Post('2fa/verify')
  async verify2fa(@Req() request: Request, @Body('token') token: string) {
    const user = request.cookies['sessionToken'];
    const userData = await this.authService.decrypt(user);
    if (!userData) return;
    const { id } = userData.payload;
    console.log(`Verifying token for user ${id}`);
    const valid = await this.speakeasyService.verifyToken(id as string, token);
    if (valid) await this.speakeasyService.update2faStatus(id as string);
    return { success: valid };
  }

  @Post('send-email-verification-link')
  async sendVerificaitonLink(@Body('email') email: string) {
    const verificationLink =
      await this.verificationLink.generateVerificationLink(email);
    return this.authService.sendVerificationEmail(email, verificationLink);
  }

  @Post('verify-email')
  async verifyEmail(
    @Body('email') email: string,
    @Body('token') token: string,
  ) {
    return await this.authService.verifyEmail(email, token);
  }

  @Get('logout')
  logout(@Res({ passthrough: true }) response: Response) {
    return this.authService.logout(response);
  }
}
