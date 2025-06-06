import { z } from "zod";
import { createError } from "../utils/errors.util";
import { HttpStatus } from "../types/api.type";

export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const registerSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const validateLogin = (data: unknown) => {
  try {
    return loginSchema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw createError(
        HttpStatus.BAD_REQUEST,
        "Validation error",
        "VALIDATION_ERROR",
        error.errors
      );
    }
    throw error;
  }
};

export const validateRegister = (data: unknown) => {
  try {
    return registerSchema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw createError(
        HttpStatus.BAD_REQUEST,
        "Validation error",
        "VALIDATION_ERROR",
        error.errors
      );
    }
    throw error;
  }
};
