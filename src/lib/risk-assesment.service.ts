import geoip from 'geoip-lite';
import { Request } from 'express';
import { createHash } from 'crypto';
import { Lookup } from 'geoip-lite';
import { Injectable } from '@nestjs/common';
import { LoginDto } from 'src/auth/dto/login-dto';
import { PrismaService } from 'src/prisma/prisma.service';
@Injectable()
export class RiskAssesmentService {
  private threatLevel: number = 0;
  constructor(private readonly prisma: PrismaService) {}

  async getThreatLevel(loginDto: LoginDto, request: Request) {
    //get threat level
    const { ipAddress = '', email = '' } = loginDto;
    await this.geoipAssessment(ipAddress, email);
    await this.fingerprintingAccessment(request, email, ipAddress);
    return this.threatLevel
  }

  async geoipAssessment(ipAddress: string, email: string) {
    const geo = geoip.lookup(ipAddress);
    if (!geo) return this.threatLevel;
    const { region, country, timezone, city }: Lookup = geo;

    try {
      const user = await this.prisma.user.findFirst({
        where: {
          email: email,
        },
        select: {
          geoData: true,
        },
      });
      

      if (!user?.geoData) return this.threatLevel;

      const existingGeoData = user?.geoData;
      const {
        country: existingCountry,
        region: existingRegion,
        timezone: existingTimezone,
        city: existingCity,
      } = existingGeoData;

      if (region !== existingRegion) this.threatLevel += 15;
      if (country !== existingCountry) this.threatLevel += 15;
      if (timezone !== existingTimezone) this.threatLevel += 15;
      if (city !== existingCity) this.threatLevel += 15;

      const geoData = user?.geoData;
      if (!geoData) {
        try {
          await this.prisma.user.update({
            where: {
              email: email,
            },
            data: {
              geoData: {
                update: {
                  region,
                  country,
                  timezone,
                  city,
                },
              },
            },
          });
        } catch (error) {
          console.error(`Error updating geo data: ${error}`);
        }
      }
    } catch (error) {
      console.error(`Error finding geo data: ${error}`);
    }
  }

  async fingerprintingAccessment(
    request: Request,
    email: string,
    ipAddress: string,
  ) {
    //get device fingerPrint
    console.error(`Starting fingerprint accessment for ${email}`);
    const userAgent = request.headers['user-agent'] || '';
    const acceptLanguage = request.headers['accept-language'] || '';
    const fingerPrint = `${userAgent}-${acceptLanguage}-${ipAddress}`;
    const hash = createHash('sha256').update(fingerPrint).digest('hex');

    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
      select: {
        lastKnownDevice: true,
        lastLoginIp: true,
      },
    });

    if (!user) return;

    const { lastKnownDevice, lastLoginIp } = user;

    if (lastKnownDevice !== hash) this.threatLevel += 15;
    if (lastLoginIp !== ipAddress) this.threatLevel += 15;

    await this.prisma.user.update({
      where: {
        email: email,
      },
      data: {
        lastKnownDevice: hash,
        lastLoginIp: ipAddress,
      },
    });
  }
}
