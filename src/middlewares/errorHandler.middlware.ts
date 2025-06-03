import { ZodError } from "zod";
import mongoose from "mongoose";
import { Response } from "express";
import { HttpStatus } from "../types/api.types";
import { AppError } from "../utils/errors.util";
import { ApiResponseBuilder } from "../utils/apiResponse.util";

interface MongoError extends Error {
  code: number;
  keyPattern: Record<string, unknown>;
}

const errorHandler = (
  err: Error | AppError | ZodError | MongoError,
  res: Response
): Response => {
  // Handle AppError instances (our custom errors)
  if (err instanceof AppError) {
    return ApiResponseBuilder.error(res, {
      message: err.message,
      statusCode: err.statusCode,
      code: err.code,
      details: err.details,
    });
  }

  // Handle Zod validation errors
  if (err instanceof ZodError) {
    return ApiResponseBuilder.error(res, {
      message: "Validation error",
      statusCode: HttpStatus.BAD_REQUEST,
      code: "VALIDATION_ERROR",
      details: err.errors,
    });
  }

  // Handle MongoDB CastError (e.g., invalid ObjectId)
  if (err instanceof mongoose.Error.CastError) {
    return ApiResponseBuilder.error(res, {
      message: `Invalid value for ${err.path}: ${err.value}`,
      statusCode: HttpStatus.BAD_REQUEST,
      code: "CAST_ERROR",
    });
  }

  // Handle Mongoose validation error
  if (err instanceof mongoose.Error.ValidationError) {
    const errors = Object.values(err.errors).map(
      (e: mongoose.Error.CastError | mongoose.Error.ValidatorError) => e.message
    );
    return ApiResponseBuilder.error(res, {
      message: `Validation error: ${errors.join(", ")}`,
      statusCode: HttpStatus.BAD_REQUEST,
      code: "VALIDATION_ERROR",
    });
  }

  // Handle MongoDB duplicate key error
  if ((err as MongoError).code === 11000) {
    const field = Object.keys((err as MongoError).keyPattern)[0];
    return ApiResponseBuilder.error(res, {
      message: `Duplicate value for field: ${field}`,
      statusCode: HttpStatus.CONFLICT,
      code: "DUPLICATE_KEY",
      details: { field },
    });
  }

  // Handle JWT errors
  if (err.name === "JsonWebTokenError") {
    return ApiResponseBuilder.error(res, {
      message: "Invalid token. Please log in again.",
      statusCode: HttpStatus.UNAUTHORIZED,
      code: "INVALID_TOKEN",
    });
  }

  if (err.name === "TokenExpiredError") {
    return ApiResponseBuilder.error(res, {
      message: "Token has expired. Please log in again.",
      statusCode: HttpStatus.UNAUTHORIZED,
      code: "TOKEN_EXPIRED",
    });
  }

  // Log unexpected errors in production
  if (process.env.NODE_ENV === "production") {
    console.error("❌ Unexpected error:", err);
  }

  // Default fallback for unhandled errors
  return ApiResponseBuilder.error(res, {
    message: "Internal server error",
    statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
    code: "INTERNAL_SERVER_ERROR",
    details: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });
};

export default errorHandler;
export { errorHandler };
