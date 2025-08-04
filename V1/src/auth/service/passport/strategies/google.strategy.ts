import {
  Strategy,
  StrategyOptions,
  Profile,
  VerifyCallback,
} from 'passport-google-oauth20';
import { PassportStrategy, AuthModuleOptions } from '@nestjs/passport';
import { PrismaService } from 'src/prisma/prisma.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';

/**
 * Google strategy for authenticaing users with google
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy) {
  public successRedirect: string;
  public failureRedirect: string;
  /**
   *
   * @param prisma -Prisma instance for communicating with the database
   * @param options -Additional options for authentication
   */
  constructor(
    private readonly prisma: PrismaService,
    private readonly options: AuthModuleOptions,
  ) {
    super({
      authorizationURL: process.env.AUTHORIZATION_URL,
      tokenURL: process.env.TOKEN_URL,
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope:['profile', 'email'],
    } as StrategyOptions);

    this.successRedirect =
      this.options['successdirect'] || `/auth/successRedirect`;
    this.failureRedirect =
      this.options['failureRedirect'] || '/auth/failureRedirect';
  }
  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
    const {
      email = '',
      email_verified,
      family_name,
      name = '',
      picture,
      profile: profiles,
    } = profile._json;
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });
    this.successRedirect = this.options['successdirect'] || `/auth/successRedirect/${email}`;
    if (!user) {
      const user = await this.prisma.user.create({
        data: {
          email: email.toLowerCase(),
          emailVerified: email_verified,
          password: 'google',
          username: name,
          provider: profile.provider,
        },
      });
      return user;
    } else if (user) {
      const { provider, email } = user;
      return `User with email ${email} already exists with ${provider} provider `;
    } else {
      throw new UnauthorizedException();
    }
  }
}
