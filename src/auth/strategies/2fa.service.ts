import { PrismaService } from "src/prisma/prisma.service";
import { SpeakesayService } from "src/lib/speakesy.service";
export class TwoFactorService {
  constructor(private readonly prisma: PrismaService) {}
}