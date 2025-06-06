import bcrypt from "bcryptjs";
import crypto from "crypto";
import { AuthModel } from "../models/auth.model";
import { generateTokens, verifyToken } from "../utils/auth.util";
import {
  TAuthTokens,
  TAuthUser,
  TLoginUserInput,
  TRegisterUserInput,
  TRefreshTokenInput,
} from "../types";
import { createError } from "../utils/errors.util";
import { validatePassword } from "../validators/password.validator";
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
} from "../utils/email.util";
import { User } from "../models/user.model";
import { HttpStatus } from "../types/api.type";
import { Types } from "mongoose";
import { Document } from "mongoose";

const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours

interface IUser extends Document {
  _id: Types.ObjectId;
  email: string;
  password: string;
  name?: string;
  isEmailVerified: boolean;
  loginAttempts: number;
  lockUntil?: Date;
  lastLogin?: Date;
  sessions: Array<{
    refreshToken: string;
    deviceInfo: string;
    ipAddress: string;
    lastActive: Date;
    createdAt: Date;
  }>;
  comparePassword: (password: string) => Promise<boolean>;
}

export const registerUser = async (
  input: TRegisterUserInput
): Promise<TAuthUser> => {
  const existingUser = await AuthModel.findOne({ email: input.email });
  if (existingUser) {
    throw createError(409, "Email already in use", "Conflict");
  }

  if (!validatePassword(input.password)) {
    throw createError(
      400,
      "Password does not meet security requirements",
      "Bad Request"
    );
  }

  const hashedPassword = await bcrypt.hash(input.password, SALT_ROUNDS);
  const verificationToken = await crypto.randomBytes(32).toString("hex");
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  const user = new AuthModel({
    email: input.email,
    password: hashedPassword,
    emailVerificationToken: verificationToken,
    emailVerificationExpires: verificationExpires,
  });

  await user.save();
  await sendVerificationEmail(user.email, verificationToken);

  return user;
};

export const verifyEmail = async (token: string): Promise<void> => {
  const user = await AuthModel.findOne({
    emailVerificationToken: token,
    emailVerificationExpires: { $gt: Date.now() },
  });

  if (!user) {
    throw createError(
      400,
      "Invalid or expired verification token",
      "Bad Request"
    );
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = null;
  user.emailVerificationExpires = null;
  await user.save();
};

export const loginUser = async (
  input: TLoginUserInput,
  deviceInfo: string,
  ipAddress: string
): Promise<TAuthTokens> => {
  const user = (await AuthModel.findOne({ email: input.email })) as IUser;
  if (!user) {
    throw createError(401, "Invalid credentials", "Unauthorized");
  }

  if (user.lockUntil && user.lockUntil > new Date()) {
    throw createError(
      401,
      "Account is locked. Try again later",
      "Unauthorized"
    );
  }

  const isPasswordValid = await bcrypt.compare(input.password, user.password);
  if (!isPasswordValid) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      user.lockUntil = new Date(Date.now() + LOCK_TIME);
    }
    await user.save();
    throw createError(401, "Invalid credentials", "Unauthorized");
  }

  if (!user.isEmailVerified) {
    throw createError(403, "Please verify your email first", "Forbidden");
  }

  const tokens = await generateTokens({
    userId: user._id.toString(),
    email: user.email,
  });

  // Update user session
  user.loginAttempts = 0;
  user.lockUntil = undefined;
  user.lastLogin = new Date();
  user.sessions.push({
    refreshToken: tokens.refreshToken,
    deviceInfo,
    ipAddress,
    lastActive: new Date(),
    createdAt: new Date(),
  });

  // Keep only last 5 sessions
  if (user.sessions.length > 5) {
    user.sessions = user.sessions.slice(-5);
  }

  await user.save();
  return tokens;
};

export const refreshTokens = async (
  input: TRefreshTokenInput,
  deviceInfo: string,
  ipAddress: string
): Promise<TAuthTokens> => {
  try {
    const decoded = verifyToken(input.refreshToken, "refresh");
    const user = (await AuthModel.findById(decoded.userId)) as IUser;

    if (!user) {
      throw createError(401, "Invalid refresh token", "Unauthorized");
    }

    const session = user.sessions.find(
      (s) => s.refreshToken === input.refreshToken
    );
    if (!session) {
      throw createError(401, "Invalid refresh token", "Unauthorized");
    }

    const tokens = generateTokens({
      userId: user._id.toString(),
      email: user.email,
    });

    // Update session
    session.refreshToken = tokens.refreshToken;
    session.lastActive = new Date();
    session.deviceInfo = deviceInfo;
    session.ipAddress = ipAddress;

    await user.save();
    return tokens;
  } catch {
    throw createError(401, "Invalid refresh token", "Unauthorized");
  }
};

export const logoutUser = async (
  userId: string,
  refreshToken: string
): Promise<void> => {
  const user = await AuthModel.findById(userId);
  if (!user) return;

  user.sessions = user.sessions.filter((s) => s.refreshToken !== refreshToken);
  await user.save();
};

export const requestPasswordReset = async (email: string): Promise<void> => {
  const user = await AuthModel.findOne({ email });
  if (!user) return; // Don't reveal if email exists

  const resetToken = crypto.randomBytes(32).toString("hex");
  const resetExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

  user.passwordResetToken = resetToken;
  user.passwordResetExpires = resetExpires;
  await user.save();

  await sendPasswordResetEmail(user.email, resetToken);
};

export const resetPassword = async (
  token: string,
  newPassword: string
): Promise<void> => {
  const user = await AuthModel.findOne({
    passwordResetToken: token,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    throw createError(400, "Invalid or expired reset token", "Bad Request");
  }

  if (!validatePassword(newPassword)) {
    throw createError(
      400,
      "Password does not meet security requirements",
      "Bad Request"
    );
  }

  const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
  user.password = hashedPassword;
  user.passwordResetToken = null;
  user.passwordResetExpires = null;
  user.sessions = []; // Clear all sessions
  await user.save();
};

export const changePassword = async (
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> => {
  const user = await AuthModel.findById(userId);
  if (!user) {
    throw createError(404, "User not found", "Not Found");
  }

  const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
  if (!isPasswordValid) {
    throw createError(401, "Current password is incorrect", "Unauthorized");
  }

  if (!validatePassword(newPassword)) {
    throw createError(
      400,
      "New password does not meet security requirements",
      "Bad Request"
    );
  }

  const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
  user.password = hashedPassword;
  user.sessions = []; // Clear all sessions on password change
  await user.save();
};

export const getProfile = async (
  userId: string
): Promise<Partial<TAuthUser>> => {
  const user = await AuthModel.findById(userId).select(
    "-password -refreshToken -sessions"
  );
  if (!user) {
    throw createError(404, "User not found", "Not Found");
  }
  return user;
};

export const deleteAccount = async (userId: string): Promise<void> => {
  await AuthModel.findByIdAndDelete(userId);
};

export const login = async (email: string, password: string) => {
  const user = (await User.findOne({ email })) as IUser;
  if (!user) {
    throw createError(
      HttpStatus.UNAUTHORIZED,
      "Invalid credentials",
      "AUTH_ERROR"
    );
  }

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    throw createError(
      HttpStatus.UNAUTHORIZED,
      "Invalid credentials",
      "AUTH_ERROR"
    );
  }

  const { accessToken, refreshToken } = generateTokens({
    userId: user._id.toString(),
    email: user.email,
  });

  return {
    user: {
      id: user._id,
      email: user.email,
      name: user.name,
    },
    accessToken,
    refreshToken,
  };
};

export const refreshToken = async (refreshToken: string) => {
  try {
    const decoded = verifyToken(refreshToken, "refresh");
    const user = (await User.findById(decoded.userId)) as IUser;

    if (!user) {
      throw createError(
        HttpStatus.UNAUTHORIZED,
        "Invalid refresh token",
        "AUTH_ERROR"
      );
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens({
      userId: user._id.toString(),
      email: user.email,
    });

    return {
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
      accessToken,
      refreshToken: newRefreshToken,
    };
  } catch {
    throw createError(
      HttpStatus.UNAUTHORIZED,
      "Invalid refresh token",
      "AUTH_ERROR"
    );
  }
};
