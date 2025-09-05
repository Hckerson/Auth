/*
 * * Email Templates Module (MVP scope per PRD)
 *
 * Includes ONLY the transactional emails required for MVP:
 *  - Verify Email (link-based)
 *  - Reset Password (link-based)
 *  - Welcome Email (post sign-up)
 *  - Login Alert (security)
 *
 * Usage:
 *   import { EmailTemplates } from 'src/lib/emails';
 *   const { subject, html, text } = EmailTemplates.verifyEmail({ verificationLink });
 *   await emailService.sendEmail({ to, subject, html, text });
 *
 * Adding a new template (future):
 *   - Define a new function returning { subject, html, text? } within EmailTemplates
 *   - Reuse shared styles/layout helpers below
 *   - Keep function args explicit (no env reads inside templates)
 *   - Provide a plain-text fallback for critical emails
 */

import { APP_NAME, APP_URL } from '../constant';

const baseStyles = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; background-color: #f8f9fa; color: #333; line-height: 1.6; }
  .email-container { max-width: 600px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden; }
  .email-header { background: #ffffff; padding: 32px 24px; text-align: center; border-bottom: 2px solid #e9ecef; }
  .logo { width: 120px; height: auto; margin-bottom: 16px; }
  .header-title { color: #0056b3; font-size: 24px; font-weight: 600; margin: 0; }
  .email-content { padding: 32px 24px; background: #ffffff; }
  .greeting { font-size: 18px; color: #333; margin-bottom: 24px; font-weight: 600; }
  .message { font-size: 16px; color: #555; margin-bottom: 24px; line-height: 1.6; }
  .cta-button { display: inline-block; padding: 16px 32px; margin: 24px 0; background: linear-gradient(135deg, #0056b3 0%, #0077cc 100%); color: #fff !important; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 600; text-align: center; min-width: 200px; box-shadow: 0 4px 12px rgba(0,86,179,0.3); }
  .email-footer { background: #f8f9fa; padding: 24px; text-align: center; border-top: 1px solid #e9ecef; }
  .footer-text { font-size: 14px; color: #6c757d; margin-bottom: 16px; }
`;

function renderLayout(
  title: string,
  contentHtml: string,
  options?: { isMarketing?: boolean },
) {
  const isMarketing = options?.isMarketing ?? false;
  const year = new Date().getFullYear();
  const footer = `
    <div class="email-footer">
      <p class="footer-text">&copy; ${year} ${APP_NAME}. All rights reserved.</p>
      <div style="margin-top:8px; font-size:12px; color:#6c757d;">
        <a href="${APP_URL}/terms" style="color:#6c757d; text-decoration:none; margin:0 8px;">Terms</a>
        <a href="${APP_URL}/privacy" style="color:#6c757d; text-decoration:none; margin:0 8px;">Privacy</a>
        <a href="${APP_URL}/support" style="color:#6c757d; text-decoration:none; margin:0 8px;">Support</a>
        ${isMarketing ? `<a href="${APP_URL}/unsubscribe" style="color:#6c757d; text-decoration:none; margin:0 8px;">Unsubscribe</a>` : ''}
      </div>
    </div>
  `;
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>${baseStyles}</style>
</head>
<body>
  <div class="email-container">
    <div class="email-header">
      <img src="https://api.kuroconnect.com/logo-transparent.png" alt="${APP_NAME} Logo" class="logo" />
      <h1 class="header-title">${APP_NAME}</h1>
    </div>
    <div class="email-content">
      ${contentHtml}
    </div>
    ${footer}
  </div>
</body>
</html>`;
}

export const EmailTemplates = {
  // * Verify Email (link-based)
  verifyEmail(params: { verificationLink: string }) {
    const title = `Verify your email for ${APP_NAME}`;
    const content = `
      <h2 class="greeting">Confirm your email</h2>
      <p class="message">Welcome to ${APP_NAME} — the intelligent academic second brain. Confirm your email to unlock your free credits and start uploading documents for AI-powered processing and semantic search.</p>
      <a href="${params.verificationLink}" class="cta-button">Verify Email</a>
      <p class="message">If the button doesn't work, copy and paste this link into your browser:<br/><a href="${params.verificationLink}">${params.verificationLink}</a></p>
      <div style="background:#f8f9fa;border-left:4px solid #0056b3;padding:16px 20px;margin:20px 0;border-radius:0 8px 8px 0;">
        <h3 style="color:#0056b3;font-size:16px;margin:0 0 8px 0;font-weight:600;">What you get</h3>
        <p style="color:#555;font-size:14px;margin:0;">• Free credits to try AI upload & metadata generation<br/>• Global semantic search across public documents<br/>• Private bookmarks and shareable collections</p>
      </div>
    `;
    const text = `Verify your email for ${APP_NAME}: ${params.verificationLink}`;
    return { subject: title, html: renderLayout(title, content), text };
  },

  // * Reset Password (link-based)
  resetPassword(params: { resetLink: string }) {
    const title = `Reset your password for ${APP_NAME}`;
    const content = `
      <h2 class="greeting">Reset your password</h2>
      <p class="message">We received a request to reset your password. Resetting your password lets you get back to uploading documents, exploring the library, and managing your credit balance securely.</p>
      <a href="${params.resetLink}" class="cta-button">Reset Password</a>
      <p class="message">If the button doesn't work, copy and paste this link into your browser:<br/><a href="${params.resetLink}">${params.resetLink}</a></p>
      <div style="background:#fff3cd;border:1px solid #ffeaa7;border-radius:8px;padding:16px;margin:20px 0;">
        <p style="color:#856404;font-size:14px;margin:0;">If you didn’t request a reset, you can safely ignore this email.</p>
      </div>
    `;
    const text = `Reset your password for ${APP_NAME}: ${params.resetLink}`;
    return { subject: title, html: renderLayout(title, content), text };
  },

  // * Welcome Email (post sign-up)
  welcomeEmail(params: { name?: string }) {
    const title = `Welcome to ${APP_NAME}!`;
    const content = `
      <h2 class="greeting">Welcome${params.name ? `, ${params.name}` : ''}! 👋</h2>
      <p class="message">You're all set. We've credited your account with free starter credits so you can experience AI-powered uploads and semantic search right away.</p>
      <div style="background:#f8f9fa;border-left:4px solid #0056b3;padding:16px 20px;margin:20px 0;border-radius:0 8px 8px 0;">
        <h3 style="color:#0056b3;font-size:16px;margin:0 0 8px 0;font-weight:600;">Get started</h3>
        <p style="color:#555;font-size:14px;margin:0;">1) Upload a PDF to auto-generate metadata<br/>2) Discover documents via global semantic search<br/>3) Save favorites with bookmarks or group them into collections</p>
      </div>
      <a href="${APP_URL}/dashboard" class="cta-button">Go to your dashboard</a>
    `;
    const text = `Welcome to ${APP_NAME}! Start by uploading a PDF or exploring the library: ${APP_URL}/dashboard`;
    return { subject: title, html: renderLayout(title, content), text };
  },

  // * Login Alert (security)
  loginAlert(params: { timeISO: string; ua?: string }) {
    const title = `${APP_NAME} login alert`;
    const dateText = new Date(params.timeISO).toLocaleString();
    const content = `
      <h2 class="greeting">New login detected</h2>
      <p class="message">A sign-in to your ${APP_NAME} account was just detected.</p>
      <div style="background:#f8f9fa;border-left:4px solid #0056b3;padding:16px 20px;margin:20px 0;border-radius:0 8px 8px 0;">
        <p style="color:#555;font-size:14px;margin:0;"><strong>Time:</strong> ${dateText}<br/><strong>Device:</strong> ${params.ua || 'Unknown'}</p>
      </div>
      <p class="message">If this was you, you're good to go. If you didn't sign in, please reset your password immediately.</p>
      <a href="${APP_URL}/reset-password" class="cta-button">Reset Password</a>
    `;
    const text = `New ${APP_NAME} login at ${dateText}. If this wasn't you, reset your password: ${APP_URL}/reset-password`;
    return { subject: title, html: renderLayout(title, content), text };
  },
};
