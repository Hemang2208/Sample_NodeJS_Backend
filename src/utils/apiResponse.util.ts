import { Response } from 'express';

type SuccessResponse<T> = {
  status: 'success';
  statusCode: number;
  data: T;
};

type ErrorResponse = {
  status: 'error';
  statusCode: number;
  message: string;
  code?: string;
  details?: unknown;
};

export class ApiResponseBuilder {
  static success<T>(res: Response, statusCode: number, data: T): Response {
    const response: SuccessResponse<T> = {
      status: 'success',
      statusCode,
      data,
    };
    return res.status(statusCode).json(response);
  }

  static error(
    res: Response,
    {
      message,
      statusCode,
      code,
      details,
    }: {
      message: string;
      statusCode: number;
      code?: string;
      details?: unknown;
    }
  ): Response {
    const response: ErrorResponse = {
      status: 'error',
      statusCode,
      message,
    };
    if (code) response.code = code;
    if (details) response.details = details;
    return res.status(statusCode).json(response);
  }
}
