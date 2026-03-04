const jwt = require('jsonwebtoken');
require('dotenv').config();

const authMiddleware = (req, res, next) => {
    // Task: Check if token is present in the header
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        // Task: Verify the token
        let jwtToken = token;
        if (token.startsWith('Bearer ')) {
            jwtToken = token.split(' ')[1];
        }

        const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

module.exports = authMiddleware;
