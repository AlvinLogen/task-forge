// Define authentication-related API endpoints
// Clean separation of concerns, easier testing and maintenance - Express routing, middleware chaining, API design patterns

const express = require('express');
const authController = require('../controllers/authController');
const {
    validateUserRegistration, 
    validateUserLogin, 
    sanitizeInput, 
    preventSQLInjection, 
    limitUserRequests
} = require('../middleware/validation');
const logger = require('../utils/logger');

const router = express.Router();

// Apply global middleware to all auth routes (Security before business logic)
router.use(sanitizeInput); // Clean input data
router.use(preventSQLInjection); //Check for SQL injection attempts
router.use(limitUserRequests(10,60000)); // 10 requests per minute per user

// User registration endpoint
router.post('/register', validateUserRegistration, async(req, res) => {
    logger.info('Registration attempt', {
        username: req.body.username, 
        email: req.body.email,
        ip: req.ip, 
        userAgent: req.get('User-Agent')
    });

    await authController.register(req, res);
});

// User login endpoint
router.post('/login', validateUserLogin, async(req, res) => {
    logger.info('Login attempt', {
        username: req.body.username, 
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });

    await authController.login(req, res);
});

// User logout endpoint
router.post('/logout', authController.requireAuth, async(req, res) => {
    logger.info('Logout attempt', {
        userId: req.session.userId, 
        ip: req.ip
    });

    await authController.logout(req, res);
});

// Get current user information
router.post('/me', authController.requireAuth, authController.getCurrentUser);

// Check if username/email is available (for registration form)
router.get('/check-availability', async(req, res) => {
    try {
        const { username, email } = req.query;

        if(!username && !email){
            return res.status(400).json({
                success: false, 
                message: 'Username or email parameter required'
            });
        }

        const { executeQuery } = require('../utils/database');

        let query = 'SELECT Username, Email FROM Users WHERE ';
        let params = {};

        if(username && email) {
            query += 'Username = @username OR Email = @email';
            params = { username, email };
        } else if (username) {
            query += 'Username = @username';
            params = { username };
        } else {
            query += 'Email = @email';
            params = { email };
        }

        const result = await executeQuery(query, params);

        const availability = {
            username: username ? !result.recordSet.some(u => u.Username === username) : null,
            email: email ? !result.recordSet.some(u => u.Email === email) : null
        };

        res.json({
            success: true, 
            data: availability
        });

    } catch (error) {
        logger.error('Availability check failed', error);
        res.status(500).json({
            success: false, 
            message: 'Availabiity check failed'
        });
    }
});

// Password strength check endpoint (for frontend validation)
router.post('/check-password-strength', (req, res) => {
    const { password } = req.body;

    if (!password){
        return res.status(400).json({
            success: false, 
            message: 'Password is required'
        });
    }

    // Password strength criteria
    const criteria = {
        minLengh: password.length >= 8, 
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /\d/.test(password),
        hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
        notCommon: !isCommonPassword(password)
    };

    // Calculate strength core
    const score = Object.values(criteria).filter(Boolean).length;
    let strength; 
    if (score === 6) strength = 'very-strong';
    else if (score >= 5) strength = 'strong';
    else if (score >= 4) strength = 'moderate';
    else if (score >= 3) strength = 'weak';
    else strength = 'very-weak';

    res.json({
        success: true,
        data: {
            strength, 
            score, 
            criteria, 
            isValid: score >= 4 // Require at least moderate strength
        }
    })
});

// Helper function to check for common passwords
function isCommonPassword(password){
    const commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'password1', '12345678', 'sunshine', 'master'
    ];

    return commonPasswords.includes(password.toLowerCase());
}

module.exports = router;