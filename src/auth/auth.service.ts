import bcrypt from 'bcryptjs';
import { Response } from 'express';
import { randomBytes } from 'node:crypto';
import { LoginDto } from './dto/login-dto';
import { Injectable } from '@nestjs/common';
import { SignUpDto } from './dto/signup-dto';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from 'generated/prisma';

@Injectable()
export class AuthService {
  private readonly secret: string;
  private readonly encodedKey: Uint8Array;
  constructor(private prisma: PrismaService) {
    this.secret = process.env.COOKIE_SECRET || '';
    if (!this.secret) {
      throw new Error('Cookie secret not found');
    }
    this.encodedKey = new TextEncoder().encode(this.secret);
  }

  async login(
    loginDto: LoginDto,
    response: Response,
  ): Promise<{ message: string; status: number }> {
    //login user and store active session in DB
    if (!loginDto.password)
      return { message: `Incomplete credentials`, status: 400 };
    const {
      email,
      password,
      rememberMe,
      twoFactorCode,
      deviceInfo,
      ipAddress,
    } = loginDto;
    const userInfo = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });
    if (!userInfo) return { message: `User not found`, status: 400 };
    const { password: hashedPassword, id } = userInfo;
    const isValid = await bcrypt.compare(password, hashedPassword);
    if (isValid) {
      if (rememberMe) {
        // Handle "Remember Me" functionality
        const rememberToken = randomBytes(32).toString('hex');
        response.cookie('rememberMe', rememberToken, {
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          httpOnly: true,
          sameSite: 'lax',
        });
        await this.storeSession(id, rememberToken);
      }
      const sessionId = await this.storeSession(id);
      const expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
      const token = await this.encrypt({ id, expiresAt, sessionId });
      response.cookie('sessionToken', token, {
        maxAge: 2 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        sameSite: 'lax',
      });

      return { message: 'login successful', status: 200 };
    }
    return { message: 'Invalid credentials', status: 400 };
  }

  async storeSession(
    // store session in database
    userId: string,
    rememberToken: string | null = '',
  ) {
    //save session to database
    const { id } = await this.prisma.session.create({
      data: {
        userId,
        rememberToken,
      },
      select: {
        id: true,
      },
    });
    return id;
  }

  async encrypt(payload: JWTPayload) {
    // encrypt payload
    const sessionToken = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2d')
      .sign(this.encodedKey);
    return sessionToken;
  }

  async decrypt(sessionToken: string | undefined = '') {
    // decrypt payload
    const payload = await jwtVerify(sessionToken, this.encodedKey, {
      algorithms: ['HS256'],
    });
    return payload;
  }

  async signUp(signUpDto: SignUpDto) {
    // register user with email and password
    // create user in database
    const { email, password, firstName, lastName } = signUpDto;
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
  }

  async logout(response: Response) {
    response.clearCookie('rememberMe');
    response.clearCookie('sessionToken  ');
    return { message: 'Logout successful' };
  }

  async verifyEmail(email: string) {}

  async validateUser(profile: any): Promise<{ status: boolean; user: User }> {
    return { status: true, user: profile };
  }

}
