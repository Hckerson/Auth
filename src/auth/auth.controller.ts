import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Req,
  Res,
  Param,
  Delete,
} from '@nestjs/common';
import { Response } from 'express';
import { LoginDto } from './dto/login-dto';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup-dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
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

  @Post()
  async verifyEmail(@Body() email:string) {
    return this.authService.verifyEmail(email);
  }

  @Get('logout')
  logout(@Res() response: Response) {
    return this.authService.logout(response);
  }

}
