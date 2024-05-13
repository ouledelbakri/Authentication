import express from "express";
import bcryt from "bcrypt";
const router = express.Router();
import { User } from "../models/User.js";
import jwt from "jsonwebtoken";

// ================== Sign up =====================
router.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    const user = await User.findOne({email});
    if(user) {
        return res.json({status: false, message: "User already exists"});
    }


    const hashpassword = await bcryt.hash(password, 10); // 
    const newUser = new User({
      username,
      email,
      password: hashpassword,
    });
  
    await newUser.save();
    return res.json({ status: true, message: "record registed" });
  });

// ================= Login ==========================
  router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "user is not registered" });
    }
  
    const validPassword = await bcryt.compare(password, user.password);
    if (!validPassword) {
      return res.json({ message: "password is incorrect" });
    }
  
    // Genrate a JWT for the user with 1h expiration 
    const token = jwt.sign({ username: user.username }, process.env.KEY, {
      expiresIn: "1h",
    });

    // Set a cookie with the JWT for secure authentification 
    res.cookie("token", token, { httpOnly: true, maxAge: 360000 });
    return res.json({ status: true, message: "login successfully" });
  });

  // ================ Logout ==================









export { router as UserRouter };