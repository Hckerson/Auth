import { PassportStrategy } from "@nestjs/passport";
import { Strategy, StrategyOptions, Profile } from "passport-github";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PrismaClient } from "generated/prisma";

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, "github") {
  constructor(private readonly prisma: PrismaClient) {
    super({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    } as StrategyOptions);
  }
  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    const {
      provider, _json, _raw
    } = profile
    console.log(_json, _raw)
    // const user = await this.prisma.user.findUnique({
    //   where: {
    //     email: email,
    //   },
    // });
    // if (!user) {
    //   const user = await this.prisma.guest.create({
    //     data: {
    //       role: "GUEST",
    //       user: {
    //         create: {
    //           email,
    //           emailVerified: email_verified,
    //           password: "google",
    //           username: name,
    //           provider: profile.provider,
    //         },
    //       },
    //     },
    //   });
    //   return user;
    // } else if (user) {
    //   const { provider, email } = user;
    //   return `User with email ${email} already exists with provider ${provider}`;
    // } else {
    //   throw new UnauthorizedException();
    // }
  }
}
