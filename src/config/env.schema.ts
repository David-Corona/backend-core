import { z } from 'zod';

export const envSchema = z.object({
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
  JWT_ACCESS_EXPIRY_MINUTES: z.coerce.number().default(15),
  JWT_REFRESH_EXPIRY_DAYS: z.coerce.number().default(30),

  BCRYPT_SALT_ROUNDS: z.coerce.number().default(12),
});

export type EnvVars = z.infer<typeof envSchema>;
