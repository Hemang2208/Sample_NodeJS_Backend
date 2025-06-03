import dotenv from "dotenv";
dotenv.config();

import app from "./app";
import connectDB from "./db/index";
import { ZodError } from "zod";

const startServer = async (): Promise<void> => {
  try {
    await connectDB();

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => {
      console.log(`🚀 Server is running at: http://localhost:${PORT}`);
    });
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      console.error("❌ Zod validation error:", error.errors);
    } else if (error instanceof Error) {
      console.error("❌ Server startup error:", error.message);
    } else {
      console.error("❌ Unknown error during startup:", error);
    }

    process.exit(1);
  }
};

startServer();
