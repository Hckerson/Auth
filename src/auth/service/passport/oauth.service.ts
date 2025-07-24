import { PassportStrategy } from "@nestjs/passport";
import {
  Strategy as ouathS,
  StrategyOptions,
  Profile,
  VerifyCallback,
} from "passport-google-oauth20";
import { PrismaClient } from "generated/prisma";
import { Injectable, UnauthorizedException } from "@nestjs/common";

@Injectable()
export class OuathStrategy extends PassportStrategy(ouathS) {
  /**
   * 
   * @param prisma 
   */
  constructor(private readonly prisma: PrismaClient) {
    super({
      authorizationURL: process.env.AUTHORIZATION_URL,
      tokenURL: process.env.TOKEN_URL,
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    } as StrategyOptions);
  }
  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback
  ) {
    const {
      email = "",
      email_verified,
      family_name,
      name = "",
      picture,
      profile: profiles,
    } = profile._json;
    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });
    if (!user) {
      const user = await this.prisma.guest.create({
        data: {
          role: "GUEST",
          user: {
            create: {
              email,
              emailVerified: email_verified,
              password: "google",
              username: name,
              provider: profile.provider,
            },
          },
        },
      });
      return user;
    } else if (user) {
      const { provider, email } = user;
      return `User with email ${email} already exists with provider ${provider}`;
    }else{
      throw new UnauthorizedException()
    }
  }
}
