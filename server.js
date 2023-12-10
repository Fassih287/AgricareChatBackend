import express from "express";
import path from "path";

import dotenv from "dotenv";

dotenv.config();

import helmet from "helmet";
import { URL } from "url";
import xss from "xss-clean";
import mongoSanitize from "express-mongo-sanitize";

import morgan from "morgan";

import "express-async-errors";

import { createServer } from "http";

//socket
import { Server } from "socket.io";

//connect DB
import connectDB from "./db/connect.js";

import cors from "cors";

//middleware
import notFoundMiddleware from "./middleware/not-found.js";
import errorHandlerMiddleware from "./middleware/error-handler.js";
import authenticateUser from "./middleware/auth.js";

//routes
import authRoute from "./routes/auth.js";
import chatRoute from "./routes/chat.js";
import messageRoute from "./routes/message.js";
import chatAgri from "./routes/chatRoute.js";
import messageAgriRoute from './routes/messageRoute.js';

const app = express();

if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(xss());
app.use(mongoSanitize());

app.get("/", (req, res) => {
  res.send("Server Running!");
});

app.use("/api/v1/auth", authRoute);
app.use("/api/v1/chat", authenticateUser, chatRoute);
app.use("/api/v1/message", authenticateUser, messageRoute);
app.use("/api/v1/chatAgri",chatAgri);
app.use("/api/v1/messageAgri",messageAgriRoute)

app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

const port = process.env.PORT || 5000;
const server = createServer(app);

const start = async () => {
  try {
    console.log(process.env.MONGO_URI)
    await connectDB(process.env.MONGO_URI);
    server.listen(port, () =>
      console.log(`Server Running on port : ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();

const io = new Server(server, {
  pingTimeout: 60000,
  cors: {
    origin: "*",
  },
});

io.on("connection", (socket) => {
  //connected to correct id
  console.log("|Connected|")
  socket.on("setup", (userData) => {
    // console.log(userData)
    socket.join(userData._id);

    socket.emit("connected");
  });

  socket.on("join-chat", (room) => {
    socket.join(room);
    console.log(room)
  });

  socket.on("typing", (room) => socket.in(room).emit("typing"));
  socket.on("stop-typing", (room) => socket.in(room).emit("stop-typing"));

  socket.on("new-message", (newMessageReceived) => {
    let chat = newMessageReceived.chat;

    if (!chat.users) return console.log(`chat.users not defined`);

    chat.users.forEach((user) => {
      if (user._id === newMessageReceived.sender._id) return;

      socket.in(user._id).emit("message-received", newMessageReceived);
    });
  });

  socket.off("setup", () => {
    socket.leave(userData._id);
  });
});
