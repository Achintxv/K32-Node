// testing route

import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import userModel from '../models/user.model.js';

const router = express.Router();

// Login handler
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: "Invalid credentials!" });

        // find the user using email
        const user = await userModel.findOne({ email }).select("+password");
        if (!user) return res.status(404).json({ success: false, message: "Invalid credentials!" });

        // comparing the hashed password
        const isMatchedPassword = await bcrypt.compare(password, user.password);
        if (!isMatchedPassword) return res.status(409).json({ success: false, message: "Incorrect password!" });

        return res.status(200).json({ success: true, message: "Login successfully!" });
    } catch (error) {
        return res.status(500).json({ success: false, message: "An unexpected error occurred while trying to login!" });
    }
};

export const signup = async (req, res) => {
    console.log("Signup route is working!");
  
    try {
      const { name, email, password } = req.body;
      if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "Invalid credentials!" });
      }
  
      const isDuplicate = await userModel.findOne({ email });
      if (isDuplicate) {
        return res.status(409).json({ success: false, message: `Email ${email} already exists!` });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const user = await userModel.create({
        name,
        email,
        password: hashedPassword
      });
  
      // remove password from the response
      user.password = undefined;
  
      return res.status(201).json({ success: true, message: "User signed up successfully!", user });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ success: false, message: "An unexpected error occurred while trying to signup!" });
    }
  };
  

// Attach routes to router
router.post('/auth/login', login); // api/auth/login
router.post('/auth/signup', signup);

export default router;