import { TApiResponse } from "../types";
import { Response } from "express";

// Types
type SuccessResponse<T> = {
  success: true;
  data?: T;
  message?: string;
  timestamp: string;
};

type ErrorResponse = {
  success: false;
  message: string;
  error: string;
  details?: unknown;
  timestamp: string;
};

// Response functions
export const successResponse = <T>(
  data?: T,
  message?: string
): SuccessResponse<T> => ({
  success: true,
  ...(data && { data }),
  ...(message && { message }),
  timestamp: new Date().toISOString(),
});

export const errorResponse = (
  message: string,
  error: string,
  details?: unknown
): ErrorResponse => ({
  success: false,
  message,
  error,
  ...(details !== undefined && { details }),
  timestamp: new Date().toISOString(),
});

// Express response helpers
export const sendSuccess = <T>(
  res: Response,
  data?: T,
  message?: string
): Response => {
  return res.json(successResponse(data, message));
};

export const sendError = (
  res: Response,
  message: string,
  error: string,
  details?: unknown
): Response => {
  return res.json(errorResponse(message, error, details));
};

export const createApiResponse = <T>(
  success: boolean,
  message: string,
  data?: T
): TApiResponse<T> => ({
  success,
  message,
  ...(data && { data }),
  timestamp: new Date().toISOString(),
});
