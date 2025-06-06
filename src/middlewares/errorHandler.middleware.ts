import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import mongoose from "mongoose";
import { errorResponse } from "../utils/apiResponse.util";

const handleError = (error: unknown, res: Response) => {
  if (error instanceof ZodError) {
    return res
      .status(400)
      .json(
        errorResponse("Validation error", "VALIDATION_ERROR", error.errors)
      );
  }

  // Handle MongoDB errors
  if (error instanceof mongoose.Error) {
    if (error instanceof mongoose.Error.ValidationError) {
      const errors = Object.values(error.errors).map((e) => e.message);
      return res
        .status(400)
        .json(
          errorResponse(
            `Validation error: ${errors.join(", ")}`,
            "VALIDATION_ERROR"
          )
        );
    }

    if (error instanceof mongoose.Error.CastError) {
      return res
        .status(400)
        .json(
          errorResponse(
            `Invalid value for ${error.path}: ${error.value}`,
            "CAST_ERROR"
          )
        );
    }
  }

  // Handle JWT errors
  if (error instanceof Error) {
    if (error.name === "JsonWebTokenError") {
      return res
        .status(401)
        .json(
          errorResponse("Invalid token. Please log in again.", "INVALID_TOKEN")
        );
    }

    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json(
          errorResponse(
            "Token has expired. Please log in again.",
            "TOKEN_EXPIRED"
          )
        );
    }
  }

  // Log unexpected errors in production
  if (process.env.NODE_ENV === "production") {
    console.error("Unexpected error:", error);
  }

  // Default error response
  return res
    .status(500)
    .json(
      errorResponse(
        "Internal server error",
        "INTERNAL_SERVER_ERROR",
        process.env.NODE_ENV === "development" ? error : undefined
      )
    );
};

export const errorHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  handleError(error, res);
  next();
};
