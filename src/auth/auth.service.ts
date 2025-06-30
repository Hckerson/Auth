import bcrypt from 'bcryptjs';
import { Response } from 'express';
import { randomBytes } from 'node:crypto';
import { LoginDto } from './dto/login-dto';
import { Injectable } from '@nestjs/common';
import { SignUpDto } from './dto/signup-dto';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { PrismaService } from 'src/prisma/prisma.service';

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
        const rememberToken = randomBytes(32).toString('hex')
        response.cookie('rememberMe', rememberToken, {
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          httpOnly: true,
          sameSite: 'lax',
        });
        await this.storeSession(id, null, rememberToken);
      }
      const expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
      const token = await this.encrypt({ id, expiresAt });
       await this.storeSession(id, token);
      response.cookie('sessionId', token, {
        maxAge: 2 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        sameSite: 'lax',
      });
      return { message: 'login successful', status: 200 };
    }
    return { message: 'Invalid credentials', status: 400 };
  }

  async storeSession(userId: string, token: string | null = '', rememberToken: string| null = '') {
    //save session to database
    const { id } = await this.prisma.session.create({
      data: {
        userId,
        token,
        rememberToken
      },
      select: {
        id: true,
      },
    });
    return id;
  }

  async encrypt(payload: JWTPayload) {
    const sessionToken = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2d')
      .sign(this.encodedKey);
    return sessionToken;
  }

  async decrypt(sessionToken: string | undefined = '') {
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

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto) {
    return `This action updates a #${id} ath`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
