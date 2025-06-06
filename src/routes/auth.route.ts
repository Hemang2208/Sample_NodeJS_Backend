import { Router } from "express";
import { validate } from "../validators/auth.validator";
import { authenticate } from "../middlewares/auth.middleware";
import * as authController from "../controllers/auth.controller";
import {
  loginSchema,
  registerSchema,
  passwordChangeSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  refreshTokenSchema,
} from "../zod/auth.zod";

const router = Router();

router.post(
  "/register",
  validate({ body: registerSchema }),
  authController.register
);

router.post("/login", validate({ body: loginSchema }), authController.login);

router.post(
  "/refresh-token",
  validate({ body: refreshTokenSchema }),
  authController.refreshToken
);

router.post(
  "/forgot-password",
  validate({ body: passwordResetRequestSchema }),
  authController.forgotPassword
);

router.post(
  "/reset-password",
  validate({ body: passwordResetSchema }),
  authController.resetPassword
);

router.use(authenticate);

router.get("/profile", authController.getProfile);

router.post(
  "/change-password",
  validate({ body: passwordChangeSchema }),
  authController.changePassword
);

router.post("/logout", authController.logout);

export default router;
