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
  login(
    @Body() createAuthDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(createAuthDto, response);
  }

  @Post('signup')
  signup(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post()
  verifyEmail(@Body() createAuthDto: SignUpDto) {}
  @Get()
  findAll() {
    return this.authService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
