import dotenv from "dotenv";
dotenv.config();

export const config = {
  port: process.env.PORT,
  env: process.env.NODE_ENV,
  jwt: {
    accessTokenSecret: process.env.JWT_ACCESS_SECRET,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET,
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY,
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY,
  },
  db: {
    uri: process.env.MONGODB_URI,
  },
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict" as const,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  clientUrl: process.env.CLIENT_URL,
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || "587"),
    secure: process.env.EMAIL_SECURE === "true",
    user: process.env.EMAIL_USER || "",
    password: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM,
  },
  mongoUri: process.env.MONGODB_URI,
  nodeEnv: process.env.NODE_ENV,
};
