const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const authRouter = require("./routers/authRouter");
const postRouter = require('./routers/postRouter');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Database Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('Database connected');

    // Routes (imported AFTER connection is established)
    app.use('/api/auth', authRouter);
    app.use('/api/posts', postRouter);

    app.get('/', (req, res) => {
      res.status(200).json("Hello from the server");
    });

    // Start Server
    const port = 5000;
    app.listen(port, () => {
      console.log(`Server is running on port ${port} successfully.`);
    });
  })
  .catch((err) => {
    console.error('Database connection failed:', err);
    process.exit(1); // Exit on connection failure
  });