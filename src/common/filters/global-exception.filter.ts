import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { PinoLogger } from 'nestjs-pino';
import { Request, Response } from 'express';

interface ErrorResponse {
  statusCode: number;
  code: string;
  message: string | string[];
  details?: any;
  timestamp: string;
  path: string;
  method: string;
  requestId?: string;
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(GlobalExceptionFilter.name);
  }

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    const requestId = (request.id as string) || 'unknown';

    const errorResponse = this.buildErrorResponse(exception, request, requestId);

    this.logError(exception, errorResponse, request);

    httpAdapter.reply(response, errorResponse, errorResponse.statusCode);
  }

  private buildErrorResponse(exception: unknown, request: Request, requestId: string): ErrorResponse {
    let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = 'Internal server error';
    let code = 'INTERNAL_SERVER_ERROR';
    let details: any = undefined;

    // Handle NestJS HttpException (includes custom errors)
    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
        code = this.getErrorCodeFromStatus(statusCode);
      } else if (typeof exceptionResponse === 'object') {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || message;
        code = responseObj.code || this.getErrorCodeFromStatus(statusCode);
        details = responseObj.details;

        // Handle validation errors (class-validator)
        if (Array.isArray(responseObj.message)) {
          message = responseObj.message;
          code = 'VALIDATION_ERROR';
        }
      }
    }
    // Handle generic errors
    else if (exception instanceof Error) {
      message = exception.message || message;
      code = exception.name || code;
    }

    // In production, hide internal error details for 500 errors
    if (process.env.NODE_ENV === 'production' && statusCode === 500) {
      message = 'Internal server error';
      details = undefined;
    }

    return {
      statusCode,
      code,
      message,
      ...(details && { details }),
      timestamp: new Date().toISOString(),
      path: request.path,
      method: request.method,
      requestId,
    };
  }

  private logError(exception: unknown, errorResponse: ErrorResponse, request: Request): void {
    const { statusCode, code, message, requestId } = errorResponse;

    const logContext = {
      statusCode,
      code,
      message,
      requestId,
      method: request.method,
      path: request.path,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    };

    // 5xx errors - error level
    if (statusCode >= 500) {
      this.logger.error({
        msg: `[${requestId}] ${code}: ${message}`,
        stack: exception instanceof Error ? exception.stack : JSON.stringify(exception),
        ...logContext,
      });
    }
    // 4xx errors - warn level
    else if (statusCode >= 400) {
      this.logger.warn({
        msg: `[${requestId}] ${code}: ${message}`,
        ...logContext,
      });
    }
  }

  private getErrorCodeFromStatus(status: number): string {
    const codeMap: Record<number, string> = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED',
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      405: 'METHOD_NOT_ALLOWED',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE_ENTITY',
      429: 'TOO_MANY_REQUESTS',
      500: 'INTERNAL_SERVER_ERROR',
      502: 'BAD_GATEWAY',
      503: 'SERVICE_UNAVAILABLE',
      504: 'GATEWAY_TIMEOUT',
    };
    return codeMap[status] || 'UNKNOWN_ERROR';
  }
}
