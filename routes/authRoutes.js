// routes/authRoutes.js
const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const transporter = require("../services/mailService")
const admin = require('firebase-admin');
const serviceAccount = require('../services/firebaseSMSKey.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ultron-b2d6c.firebaseio.com"
});

// Register
router.post('/register', async (req, res) => {
    const { email, phone, password, role } = req.body;
    console.log(req.body, 'find register body data')
    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create a new user
        const user = new User({ email, phone, password, role });
        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
router.post('/login', async (req, res) => {
    const { id, password } = req.body;
    console.log(req.body, 'find login body data')
    try {
        // Find user by email or phone number
        const user = await User.findOne({
            $or: [{ email: id }, { phone: id }],
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid user ID' });
        }

        // Check if the password matches
        const isMatch = await bcrypt.compare(password, user.password);
        console.log('Entered password:', password);
        console.log('Stored password hash:', user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect Password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '2d' }
        );

        // Return the tokenaaa
        res.json({ token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Request Password Reset
router.post('/reset-password', async (req, res) => {
    const { id } = req.body;

    try {
        // Find the user by email or phone number
        const user = await User.findOne({
            $or: [{ email: id }, { phone: id }],
        });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpExpiresIn = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

        user.resetOtp = otp;
        user.resetOtpExpires = otpExpiresIn;
        await user.save();


        if (id.includes('@')) {
            // OTP for email

            // Send OTP via email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: id,
                subject: 'Your OTP for Verification',
                text: `Your OTP is: ${otp}`,
            };

            await transporter.sendMail(mailOptions);
            console.log(`OTP ${otp} sent to email:`, id);
            return res.status(200).json({ message: `OTP ${otp} sent to email` });

        } else {
            // OTP for phone number via Firebase
            const phoneNumber = id;
            const testSMS = await admin.messaging().send({
                token: phoneNumber,
                notification: {
                    title: 'Your OTP for Verification',
                    body: `Your OTP is: ${otp}`,
                },
            });

            console.log('OTP sent:', testSMS);
            res.status(200).json({ message: `OTP ${otp} sent to your mobile number` });

            // Generate a custom token (Firebase requires a token or session for OTP)
            // const otpSession = await admin.auth().createSessionCookie(phoneNumber, { expiresIn: 600000 });

            // // Send OTP via Firebase SMS using the session
            // admin.auth().createUserWithPhoneNumber(phoneNumber)
            //     .then((userRecord) => {
            //         console.log(userRecord, 'find userRecord')
            //         console.log(`OTP ${otpSession} sent to phone:`, phoneNumber);
            //         return res.status(200).json({ message: `OTP sent to your mobile number: ${phoneNumber}`, otpSession });
            //     })
            //     .catch((error) => {
            //         console.error('Error sending OTP via Firebase:', error);
            //         return res.status(500).json({ message: 'Error sending OTP' });
            //     });
        }
        // Generate a random 6-digit OTP
        // const otp = crypto.randomInt(100000, 999999).toString();
        // const otpExpiresIn = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

        // // Store OTP and expiration time in the user's document
        // user.resetOtp = otp;
        // user.resetOtpExpires = otpExpiresIn;
        // await user.save();

        // // node mailer
        // if (id.includes('@')) {
        //     const mailOptions = {
        //         from: process.env.EMAIL_USER,
        //         to: id,
        //         subject: 'Your OTP for Verification',
        //         text: `Your OTP is: ${otp}`,
        //     };

        //     try {
        //         await transporter.sendMail(mailOptions);
        //         console.log('OTP sent to email:', id);
        //     } catch (error) {
        //         console.error('Error sending OTP email:', error);
        //     }
        // } 
        // You would also send the OTP via email or SMS here
        // console.log(`Generated OTP: ${otp}`);

        // res.status(200).json({ message: `OTP sent to your email/phone and the OTP is ${otp}` });
    } catch (error) {
        console.error('Error generating OTP:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
    const { id, otp } = req.body; // 'id' can be email or phone

    try {
        // Find user by email or phone number
        const user = await User.findOne({
            $or: [{ email: id }, { phone: id }],
        });

        // Check if user exists
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Check if OTP exists and matches
        if (!user.resetOtp || user.resetOtp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        // Check if OTP has expired
        if (user.resetOtpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP has expired' });
        }

        // OTP is valid
        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset Password
router.post('/update-password', async (req, res) => {
    const { id, newPassword, confirmPassword } = req.body;

    try {
        // Validate passwords
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        // Find user by email or phone
        const user = await User.findOne({
            $or: [{ email: id }, { phone: id }],
        });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Hash the new password
        // const salt = await bcrypt.genSalt(10);
        // const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the password and clear the OTP fields
        user.password = newPassword;
        user.resetOtp = undefined;
        user.resetOtpExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
