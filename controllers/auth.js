import { StatusCodes } from "http-status-codes";
import User from "../models/user.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import {
  BadRequestError,
  NotFoundError,
  UnAuthenticatedError,
} from "../errors/index.js";

const register = async (req, res) => {
  const { username, email, password, cnic, experties, role } = req.body;
  const avatar =
    "https://e7.pngegg.com/pngimages/348/800/png-clipart-man-wearing-blue-shirt-illustration-computer-icons-avatar-user-login-avatar-blue-child.png";

  if (!username || !email || !password) {
    throw new BadRequestError("Please Provide All Values");
  }

  if (!role) {
    throw new BadRequestError("Please Provide All Values");
  } else if (role == "expert" && !experties) {
    throw new BadRequestError("Please Provide All Values");
  }

  const isUserExists = await User.findOne({ email: email });

  if (isUserExists) {
    throw new BadRequestError("User with this Email Already Exists");
  }
  const minLengthRegex = /.{8,}/;
  const uppercaseRegex = /[A-Z]/;
  const lowercaseRegex = /[a-z]/;

  const isMinLengthValid = minLengthRegex.test(password);
  const isUppercaseValid = uppercaseRegex.test(password);
  const isLowercaseValid = lowercaseRegex.test(password);

  if (!isLowercaseValid || !isMinLengthValid || !isUppercaseValid) {
    throw new BadRequestError("Password Problem");
  }

  let regex = /^[a-zA-Z ]*$/;

  if (!regex.test(username)) {
    throw new BadRequestError("Error Name");
  }

  const minLengthRegexCNIC = /.{13,}/;
  const isCNICLength = minLengthRegexCNIC.test(cnic);

  if (!isCNICLength || cnic.length < 13 || cnic.length > 13) {
    throw new BadRequestError("CNIC Problem");
  }

  const hashPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    username,
    email,
    password: hashPassword,
    avatar,
  });
  const token = jwt.sign(
    {
      userId: user._id,
      username: user.username,
      userEmail: user.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_LIFETIME,
    }
  );

  res.status(StatusCodes.CREATED).json({
    _id: user._id,
    username: user.username,
    email: user.email,
    avatar: user.avatar,
    token,
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  // console.log(req.body)

  if (!email || !password) {
    throw new BadRequestError("Please Provide All the Values");
  }

  const isUser = await User.findOne({ email: email });

  if (!isUser) {
    throw new NotFoundError("Invalid Credentials");
  }

  //compare password
  const comparePassword = await bcrypt.compare(password, isUser.password);

  if (!comparePassword) {
    throw new BadRequestError(
      "Please Make Sure You have entered Correct Password!"
    );
  }
  // console.log(isUser,"USER")
  const token = jwt.sign(
    {
      userId: isUser._id,
      username: isUser.username,
      userEmail: isUser.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_LIFETIME,
    }
  );

  res.status(StatusCodes.OK).json({
    _id: isUser._id,
    username: isUser.username,
    email: isUser.email,
    avatar: isUser.avatar,
    token,
  });
};

const searchUser = async (req, res) => {
  const { search } = req.query;

  const user = await User.find({
    username: { $regex: search, $options: "i" },
  }).select("username avatar _id email bio");

  res.status(StatusCodes.OK).json(user);
};

export { register, login, searchUser };
