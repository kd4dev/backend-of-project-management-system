import express from "express";
import cors from "cors";
import healthCheckRouter from "./routes/healthcheck.routes.js";
const app = express();

//basic configuration
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

//cors configuration
app.use(
  cors({
    origin: process.env.CORSS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type"],
  }),
);

app.use("/api/v1/healthcheck", healthCheckRouter);
app.get("/", (req, res) => {
  res.send("Hello,World!");
});

export default app;
