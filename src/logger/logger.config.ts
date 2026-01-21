import { Options } from 'pino-http';

export function createPinoConfig(): Options {
  const isDev = process.env.NODE_ENV === 'development';

  return {
    level: isDev ? 'debug' : 'info',
    transport: isDev
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            singleLine: false,
          },
        }
      : undefined,
    // redact: ['req.headers.authorization'],
  };
}
