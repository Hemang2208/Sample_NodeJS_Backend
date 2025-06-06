import express, { Express } from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import { config } from "./config";
import routes from "./routes";
import { errorHandler } from "./middlewares/errorHandler.middleware";

const app: Express = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: config.clientUrl }));
app.use(helmet());
app.use(morgan("dev"));
app.use(compression());

// Global Route
app.get("/", (req, res) => {
  res.send("🚀 Server is running");
});

// Routes
app.use("/api", routes);

// Error handling
app.use(errorHandler);

export default app;
