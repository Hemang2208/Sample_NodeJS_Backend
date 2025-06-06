import { Request, Response } from "express";
import { TApiResponse, TAuthTokens, TAuthUser } from "../types";
import { createApiResponse } from "../utils/apiResponse.util";
import * as authService from "../services/auth.service";
import { config } from "../config";
import { JwtPayload } from "jsonwebtoken";
import { ZodError } from "zod";

interface AuthenticatedRequest extends Request {
  user?: JwtPayload & { userId?: string };
}

export const register = async (
  req: Request,
  res: Response<TApiResponse<{ email: string }>>
) => {
  try {
    const user = await authService.registerUser(req.body);
    return res
      .status(201)
      .json(
        createApiResponse(
          true,
          "User registered successfully. Please check your email for verification.",
          { email: user.email }
        )
      );
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Registration failed"
        )
      );
  }
};

export const verifyEmail = async (
  req: Request,
  res: Response<TApiResponse<null>>
) => {
  try {
    const { token } = req.params;
    await authService.verifyEmail(token);
    return res
      .status(200)
      .json(createApiResponse(true, "Email verified successfully"));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(400)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Invalid verification token"
        )
      );
  }
};

export const login = async (
  req: Request,
  res: Response<TApiResponse<{ accessToken: string }>>
) => {
  try {
    const deviceInfo = req.headers["user-agent"] || "Unknown";
    const ipAddress = req.ip || req.socket.remoteAddress || "Unknown";

    const tokens: TAuthTokens | null = await authService.loginUser(
      req.body,
      deviceInfo,
      ipAddress
    );

    if (!tokens) {
      return res
        .status(401)
        .json(createApiResponse(false, "Invalid email or password"));
    }

    res.cookie("refreshToken", tokens.refreshToken, config.cookie);

    return res.status(200).json(
      createApiResponse(true, "Login successful", {
        accessToken: tokens.accessToken,
      })
    );
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Login failed"
        )
      );
  }
};

export const refreshToken = async (
  req: Request,
  res: Response<TApiResponse<{ accessToken: string }>>
) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) {
      return res
        .status(400)
        .json(createApiResponse(false, "Refresh token missing"));
    }

    const deviceInfo = req.headers["user-agent"] || "Unknown";
    const ipAddress = req.ip || req.socket.remoteAddress || "Unknown";

    const tokens = await authService.refreshTokens(
      { refreshToken },
      deviceInfo,
      ipAddress
    );

    res.cookie("refreshToken", tokens.refreshToken, config.cookie);

    return res.status(200).json(
      createApiResponse(true, "Token refreshed", {
        accessToken: tokens.accessToken,
      })
    );
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(401)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Invalid refresh token"
        )
      );
  }
};

export const logout = async (
  req: AuthenticatedRequest,
  res: Response<TApiResponse<null>>
) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (req.user?.userId && refreshToken) {
      await authService.logoutUser(req.user.userId, refreshToken);
    }

    res.clearCookie("refreshToken");

    return res
      .status(200)
      .json(createApiResponse(true, "Logged out successfully"));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Logout failed"
        )
      );
  }
};

export const forgotPassword = async (
  req: Request,
  res: Response<TApiResponse<null>>
) => {
  try {
    const { email } = req.body;
    await authService.requestPasswordReset(email);
    return res
      .status(200)
      .json(
        createApiResponse(
          true,
          "If an account exists with this email, you will receive password reset instructions"
        )
      );
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error
            ? error.message
            : "Failed to send reset instructions"
        )
      );
  }
};

export const resetPassword = async (
  req: Request,
  res: Response<TApiResponse<null>>
) => {
  try {
    const { token, newPassword } = req.body;
    await authService.resetPassword(token, newPassword);
    return res
      .status(200)
      .json(createApiResponse(true, "Password has been reset successfully"));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(400)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Password reset failed"
        )
      );
  }
};

export const changePassword = async (
  req: AuthenticatedRequest,
  res: Response<TApiResponse<null>>
) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json(createApiResponse(false, "Unauthorized"));
    }

    const { currentPassword, newPassword } = req.body;
    await authService.changePassword(userId, currentPassword, newPassword);

    return res
      .status(200)
      .json(createApiResponse(true, "Password changed successfully"));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(400)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Password change failed"
        )
      );
  }
};

export const getProfile = async (
  req: AuthenticatedRequest,
  res: Response<TApiResponse<Partial<TAuthUser>>>
) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json(createApiResponse(false, "Unauthorized"));
    }

    const profile = await authService.getProfile(userId);
    return res
      .status(200)
      .json(createApiResponse(true, "Profile retrieved successfully", profile));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Failed to retrieve profile"
        )
      );
  }
};

export const deleteAccount = async (
  req: AuthenticatedRequest,
  res: Response<TApiResponse<null>>
) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json(createApiResponse(false, "Unauthorized"));
    }

    await authService.deleteAccount(userId);
    res.clearCookie("refreshToken");

    return res
      .status(200)
      .json(createApiResponse(true, "Account deleted successfully"));
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      return res
        .status(400)
        .json(createApiResponse(false, error.errors[0].message));
    }
    return res
      .status(500)
      .json(
        createApiResponse(
          false,
          error instanceof Error ? error.message : "Failed to delete account"
        )
      );
  }
};
