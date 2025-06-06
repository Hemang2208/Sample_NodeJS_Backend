import { z } from "zod";
import { authSchema } from "../zod/auth.zod";

export type TLoginUserInput = z.infer<typeof authSchema.login>;
export type TRegisterUserInput = z.infer<typeof authSchema.register>;
export type TRefreshTokenInput = z.infer<typeof authSchema.refreshToken>;
export type TForgotPasswordInput = z.infer<typeof authSchema.forgotPassword>;
export type TResetPasswordInput = z.infer<typeof authSchema.resetPassword>;

export type TAuthTokens = {
  accessToken: string;
  refreshToken: string;
};

export type TAuthTokenPayload = {
  userId: string;
  email: string;
  role?: string;
};

export type TAuthUser = {
  id: string;
  email: string;
  password: string;
  refreshToken?: string | null;
  createdAt: Date;
  updatedAt: Date;
};
