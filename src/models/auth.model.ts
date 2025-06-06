import mongoose from "mongoose";
import { TAuthUser } from "../types";

const AuthSchema = new mongoose.Schema<TAuthUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },

    password: {
      type: String,
      required: true,
    },

    refreshToken: {
      type: String,
      default: null,
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    emailVerificationToken: {
      type: String,
      default: null,
    },

    emailVerificationExpires: {
      type: Date,
      default: null,
    },

    passwordResetToken: {
      type: String,
      default: null,
    },

    passwordResetExpires: {
      type: Date,
      default: null,
    },

    loginAttempts: {
      type: Number,
      default: 0,
    },

    lockUntil: {
      type: Date,
      default: null,
    },

    lastLogin: {
      type: Date,
      default: null,
    },

    sessions: [
      {
        refreshToken: String,
        deviceInfo: String,
        ipAddress: String,
        lastActive: Date,
        createdAt: Date,
      },
    ],
  },
  {
    timestamps: true,
  }
);

AuthSchema.index({ emailVerificationToken: 1 });
AuthSchema.index({ passwordResetToken: 1 });

export const AuthModel = mongoose.model<TAuthUser>("Auth", AuthSchema);
