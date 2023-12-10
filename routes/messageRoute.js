import express from 'express';
import Message from "../models/message.js";
import { StatusCodes } from "http-status-codes";
import Chat from "../models/chat.js";
const router = express.Router();

router.route("/").post(async(req,res)=>{
    const { message, chatId, mongoId } = req.body;
    console.log(req.body,"Mees")
  if (!message || !chatId) {
    return BadRequestError("Please Provide All Fields To send Message");
  }

  let newMessage = {
    sender: mongoId,
    message: message,
    chat: chatId,
  };

  let m = await Message.create(newMessage);

  await Chat.findByIdAndUpdate(chatId, { latestMessage: m }, { new: true });

  res.status(StatusCodes.OK).json(m);
})

export default router;