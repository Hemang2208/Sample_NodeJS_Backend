import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  const message = "❌ MONGODB_URI is not defined in environment variables.";
  console.error(message);
  throw new Error(message);
}

const connectDB = async (): Promise<void> => {
  try {
    const connection = await mongoose.connect(MONGODB_URI);
    console.log(`✅ Connected to MongoDB at: ${connection.connection.host}`);
  } catch (error: unknown) {
    if (error instanceof mongoose.Error) {
      console.error("❌ Mongoose Error:", error.message);
    } else if (error instanceof Error) {
      console.error("❌ Connection Error:", error.message);
    } else {
      console.error("❌ Unknown Error:", error);
    }

    process.exit(1);
  }
};

export default connectDB;
export { connectDB };
