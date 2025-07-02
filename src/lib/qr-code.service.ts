import * as QRCode from 'qrcode';
export class QrcodeService {
  constructor() { }
  async generateQrCode(text: string) {
    try {
      return await QRCode.toDataURL(text, { errorCorrectionLevel: 'M' });
    } catch (error) {
      console.error(`Error generating QR code: ${error}`);
    }
  }
}
