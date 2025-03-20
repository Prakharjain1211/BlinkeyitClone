import jwt from "jsonwebtoken";
import UserModel from "../models/user.model.js";
const generateRefreshToken = async (userId) => {
  const token =  jwt.sign(
    { id: userId },
    process.env.SECRET_KEY_REFRESH_TOKEN,
    {
      expiresIn: "7d",
    }
  );
  const updateRefeshToken = await UserModel.updateOne(
    { _id: userId },
    { refreshToken: token }
  );
  return token;
};
export default generateRefreshToken;
