const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Import Pino logger

//Task 1: Use the `body`,`validationResult` from `express-validator` for input validation
const { body, validationResult } = require('express-validator');


const logger = pino();  // Create a Pino logger instance

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('firstName').notEmpty().withMessage('First name is required'),
    body('lastName').notEmpty().withMessage('Last name is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Validation errors in register request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();

        // Task 2: Access MongoDB collection
        const collection = db.collection("users");

        //Task 3: Check for existing email
        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;

        //Task 4: Save user details in database
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User registered successfully');
        res.json({ authtoken, email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

//Login Endpoint
router.post('/login', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    console.log("\n\n Inside login")

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Validation errors in login request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const theUser = await collection.findOne({ email: req.body.email });

        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            if (!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };

            const userName = theUser.firstName;
            const userEmail = theUser.email;

            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Internal server error', details: e.message });
    }
});

const authMiddleware = require('../middleware/authMiddleware');

// update API
router.put('/update', authMiddleware, async (req, res) => {
    // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.

    const errors = validationResult(req);

    // Task 3: Check if there are validation errors
    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const userId = req.user.id;

        if (!userId) {
            logger.error('User ID not found in the token payload');
            return res.status(400).json({ error: "User ID not found in the token payload" });
        }

        const db = await connectToDatabase();
        const collection = db.collection("users");

        const { ObjectId } = require('mongodb');
        const existingUser = await collection.findOne({ _id: new ObjectId(userId) });

        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }

        existingUser.firstName = req.body.firstName || req.body.name || existingUser.firstName;
        existingUser.lastName = req.body.lastName || existingUser.lastName;
        existingUser.updatedAt = new Date();

        const updatedUser = await collection.findOneAndUpdate(
            { _id: new ObjectId(userId) },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        const payload = {
            user: {
                id: userId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User updated successfully');

        res.json({ authtoken });
    } catch (error) {
        logger.error(error);
        return res.status(500).send("Internal Server Error");
    }
});
module.exports = router;