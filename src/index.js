import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/index.js";

const port = process.env.PORT || 8000;

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`Listening on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("Mongo DB connection error", error);
    process.exit(1);
  });
