import { Router } from "express";
import auth from "../middleware/auth.js";
import {
  loginController,
  logoutController,
  registerUserController,
  verifyEmailController,
  uploadAvatar,
  updateUserDetails,
  forgotPasswordController,
  verifyForgotPasswordOtp,
  resetpassword
} from "../controllers/user.controller.js";
import upload from "../middleware/multer.js";
const userRouter = Router();

userRouter.post("/register", registerUserController);
userRouter.post("/verify-email", verifyEmailController);
userRouter.post("/login", loginController);
userRouter.get("/logout", logoutController);
userRouter.put("/upload-avatar", auth, upload.single("avatar"), uploadAvatar);
userRouter.put("/update-user", auth, updateUserDetails);
userRouter.put("/forgot-password", forgotPasswordController);
userRouter.put("/verify-forgot-password-otp", verifyForgotPasswordOtp);
userRouter.put('/reset-password',resetpassword)
export default userRouter;
