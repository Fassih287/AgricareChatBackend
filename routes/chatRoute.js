import express from "express";
import { StatusCodes } from "http-status-codes";
import Chat from "../models/chat.js";
import User from "../models/user.js";

const router = express.Router();


router.route("/").post(async(req,res)=>{
  // console.log("hitt")
    const { userId, mongoId } = req.body;
    // console.log(userId)
    // console.log(req.body,"body");

  if (!userId) {
    return res.send("No User Exists!");
  }

  let chat = await Chat.find({
    isGroupChat: false,
    $and: [
      { users: { $elemMatch: { $eq: mongoId } } },
      { users: { $elemMatch: { $eq: userId } } },
    ],
  })
    .populate("users", "-password")
    .populate("latestMessage");

  chat = await User.populate(chat, {
    path: "latestMessage.sender",
    select: "username avatar email fullName _id",
  });

  if (chat.length > 0) {
    res.send(chat[0]);
  } else {
    const createChat = await Chat.create({
      chatName: "sender",
      isGroupChat: false,
      users: [mongoId, userId],
    });

    const fullChat = await Chat.findOne({ _id: createChat._id }).populate(
      "users",
      "-password"
    );

    res.status(StatusCodes.OK).json(fullChat);
  }
})
export default router;
