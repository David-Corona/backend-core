import { z } from 'zod';
import { envSchema, EnvVars } from './env.schema';

export function loadEnvConfig(): EnvVars {
  const parsed = envSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error('Invalid environment variables');
    console.error(z.treeifyError(parsed.error));
    process.exit(1);
  }

  return parsed.data;
}
