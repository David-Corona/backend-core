import { z } from 'zod';

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),

  DB_URL: z.string().min(1),
});

export type EnvVars = z.infer<typeof envSchema>;
