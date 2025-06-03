import cors from "cors";
import dotenv from "dotenv";
import morgan from "morgan";
import { ZodError } from "zod";
import cookieParser from "cookie-parser";
import { MongooseError } from "mongoose";
import express, { Request, Response } from "express";

// Load environment variables
dotenv.config();

// Routes
import routes from "./routes/index";

// Middlewares
import errorHandler from "./middlewares/errorHandler.middlware";
import limitRequests from "./middlewares/rateLimit.middleware";

const app = express();

// Global Middlewares
app.use(
  cors({
    origin: process.env.PUBLIC_API_BASE_URL,
    credentials: true,
  })
);
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Import authentication middleware
// import { protect } from "./middlewares/auth.middleware";

// Optional authentication middleware globally
// This will attach the user to the request object if a valid token is provided
// app.use(protect);

// Root Route
app.get("/", (_req: Request, res: Response) => {
  res.send("Ayush Bhadkhau GOD!");
});

// API Routes
app.use("/api", routes);

// Global Error Handler (should be after routes)
app.use((err: Error | ZodError | MongooseError, _req: Request, res: Response) =>
  errorHandler(err, res)
);

// Optional: Apply rate limiter globally (usually done before routes)
app.use(limitRequests);

export default app;
