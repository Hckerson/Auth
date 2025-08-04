# 🔐 Advanced Authentication System

A comprehensive, production-ready authentication system built with **NestJS** featuring multi-provider authentication, advanced security measures, and enterprise-level user management.

## 🚀 Features

- **Multi-Provider Authentication**: Local, GitHub OAuth, Google OAuth
- **Advanced Security**: Risk assessment, device fingerprinting, geoIP tracking
- **Two-Factor Authentication**: TOTP with QR code generation
- **Session Management**: Encrypted JWT sessions with remember me functionality
- **Email Integration**: Verification emails and password reset
- **Rate Limiting**: Built-in request throttling
- **API Documentation**: Swagger/OpenAPI integration
- **Geographic Security**: Location-based threat detection

## 🛡️ Security Features

- **Risk Assessment System**: Real-time threat level calculation
- **Device Fingerprinting**: Tracks user agents and device characteristics
- **GeoIP Analysis**: Compares login location with known locations
- **Threat Scoring**: Prevents login if risk level exceeds threshold
- **Encrypted Sessions**: Custom JWT encryption
- **Password Security**: bcrypt hashing

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL database
- pnpm package manager
- Environment variables configured

## ⚠️ Custom Library Patch Required

This project uses a custom version of `geoip-lite`.  
**After running `pnpm install`, you must manually copy the contents of `custom_libs/geoip-lite` into `node_modules/geoip-lite`.**

If you skip this step, the app may not work as expected.

**Steps:**

1. Run `pnpm install`
2. Copy the custom library:
   ```bash
   cp -r custom_libs/geoip-lite/* node_modules/geoip-lite/
   ```
3. Continue with your normal workflow.

> **Important**: Repeat this step every time you reinstall dependencies.

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd project

# Install dependencies
pnpm install

# Apply custom library patch
cp -r custom_libs/geoip-lite/* node_modules/geoip-lite/
```

### 2. Environment Configuration

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/auth_db"

# Authentication
COOKIE_SECRET="your-super-secret-cookie-key"
JWT_SECRET="your-jwt-secret-key"

# OAuth Providers
GITHUB_CLIENT_ID="your-github-client-id"
GITHUB_CLIENT_SECRET="your-github-client-secret"
GITHUB_CALLBACK_URL="http://localhost:3000/auth/github/callback"

GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_CALLBACK_URL="http://localhost:3000/auth/google/callback"
AUTHORIZATION_URL="https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL="https://oauth2.googleapis.com/token"

# Email Configuration
APP_USERNAME="your-email@gmail.com"
APP_PASSWORD="your-app-password"
SENDER_EMAIL="noreply@yourapp.com"

# Server
PORT=3000
```

### 3. Database Setup

```bash
# Generate Prisma client
pnpm run prisma:generate

# Run database migrations
npx prisma migrate dev

# (Optional) Seed database
npx prisma db seed
```

### 4. Running the Application

```bash
# Development mode
pnpm run start:dev

# Production mode
pnpm run start:prod

# Debug mode
pnpm run start:debug
```

## 📚 API Documentation

Once the application is running, visit:

- **Swagger UI**: `http://localhost:3000/api`
- **Health Check**: `http://localhost:3000/`

## 🔌 API Endpoints

### Authentication

- `POST /auth/login` - User login with credentials
- `POST /auth/signup` - User registration
- `POST /auth/logout` - User logout
- `POST /auth/reset-password` - Password reset

### OAuth Authentication

- `GET /auth/github` - GitHub OAuth login
- `GET /auth/github/callback` - GitHub OAuth callback
- `GET /auth/google` - Google OAuth login
- `GET /auth/google/callback` - Google OAuth callback

### Two-Factor Authentication

- `POST /auth/2fa/setup` - Setup 2FA for user
- `POST /auth/2fa/verify` - Verify 2FA token

### Email Verification

- `POST /auth/send-verification-link` - Send verification email
- `POST /auth/verify-email` - Verify email address
- `POST /auth/send-reset-password-link` - Send password reset email

## 🧪 Testing

```bash
# Unit tests
pnpm run test

# E2E tests
pnpm run test:e2e

# Test coverage
pnpm run test:cov

# Debug tests
pnpm run test:debug
```

## 🏗️ Project Structure

```
src/
├── auth/                    # Authentication module
│   ├── auth.module.ts      # Main auth module
│   ├── auth.service.ts     # Core authentication logic
│   ├── auth.controller.ts  # API endpoints
│   ├── dto/               # Data transfer objects
│   ├── entities/          # Database entities
│   └── service/
│       ├── passport/      # Passport strategies & guards
│       └── mailtrap.service.ts
├── lib/                   # Utility services
│   ├── risk-assesment.service.ts
│   ├── speakesy.service.ts
│   ├── qr-code.service.ts
│   └── verificationLink.service.ts
└── prisma/               # Database service
```

## 🔐 Security Implementation

### Risk Assessment System

The system calculates a threat level (0-100) based on:

- **GeoIP Analysis**: Compares login location with user's known locations
- **Device Fingerprinting**: Tracks user agents and device characteristics
- **IP Address Tracking**: Monitors login patterns
- **Location Changes**: Penalizes logins from new locations

### Authentication Flow

1. **Login Attempt** → Risk Assessment → Threat Level Calculation
2. **If Safe** → Validate Credentials → Create Session
3. **If 2FA Enabled** → Require TOTP Token
4. **Session Management** → Encrypted JWT Storage

## 🗄️ Database Schema

### User Model

```prisma
model User {
  id                String    @id @default(uuid())
  email             String    @unique
  password          String
  username          String    @default("")
  provider          String    @default("")
  emailVerified     Boolean   @default(false)
  twofaVerified     Boolean   @default(false)
  speakeasySecret   String?
  lastLoginIp       String?
  lastKnownDevice   String?
  sessions          Session[]
  geoData           GeoData?
}
```

## 🚀 Deployment

### Using NestJS Mau (Recommended)

```bash
# Install Mau CLI
pnpm install -g @nestjs/mau

# Deploy to AWS
mau deploy
```

### Manual Deployment

1. Build the application:

   ```bash
   pnpm run build
   ```

2. Set up environment variables for production

3. Run database migrations:

   ```bash
   npx prisma migrate deploy
   ```

4. Start the application:
   ```bash
   pnpm run start:prod
   ```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [NestJS Documentation](https://docs.nestjs.com)
- **Community**: [Discord Channel](https://discord.gg/G7Qnnhy)
- **Courses**: [NestJS Courses](https://courses.nestjs.com)
- **Enterprise Support**: [Enterprise Support](https://enterprise.nestjs.com)

## 🔗 Resources

- [NestJS Documentation](https://docs.nestjs.com)
- [NestJS Devtools](https://devtools.nestjs.com)
- [NestJS Mau](https://mau.nestjs.com) - AWS deployment platform
- [NestJS Jobs](https://jobs.nestjs.com)

## 👥 Stay in Touch

- **Author**: [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- **Website**: [https://nestjs.com](https://nestjs.com/)
- **Twitter**: [@nestframework](https://twitter.com/nestframework)

---

**Built with ❤️ using [NestJS](https://nestjs.com/)**
