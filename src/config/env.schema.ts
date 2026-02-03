import { z } from 'zod';

export const envSchema = z.object({
  // App info
  APP_NAME: z.string().default('CoreApp'),
  APP_URL: z.string().url().default('http://localhost:3000'),
  
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),

  // Database
  POSTGRES_USER: z.string().min(1),
  POSTGRES_PASSWORD: z.string().min(1),
  POSTGRES_DB: z.string().min(1),
  DATABASE_URL: z.string().min(1),
  
  // JWT
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),

  // Auth config (optional)
  JWT_ACCESS_EXPIRY_MINUTES: z.coerce.number().default(15),
  JWT_REFRESH_EXPIRY_DAYS: z.coerce.number().default(30),
  BCRYPT_SALT_ROUNDS: z.coerce.number().default(12),

  // Email
  RESEND_API_KEY: z.string().min(1),
  RESEND_FROM: z.string().email(),

  // Email token expiry (optional)
  EMAIL_VERIFICATION_EXPIRY_HOURS: z.coerce.number().default(24),
  PASSWORD_RESET_EXPIRY_MINUTES: z.coerce.number().default(60),
});

export type EnvVars = z.infer<typeof envSchema>;
