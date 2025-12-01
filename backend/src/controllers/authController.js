//Handle all user authentication operations securely
const bcrypt = require('bcryptjs');
const { executeQuery } = require('../utils/database');
const logger = require('../utils/logger');
const Joi = require('joi');

class AuthController {
    // User registration endpoint
    async register (req, res) {
        try {
            //Input validation: Prevention of malformed data, security attacks, and database errors
            const schema = Joi.object({
                username: Joi.string().alphanum().min(3).max(50).required().messages({
                    'string.alphanum': 'Username must contain only letters and numbers',
                    'string:min': 'Username must be at least 3 characters long',
                    'string:max': 'Username must not exceed 50 characters'
                }), 
                email: Joi.string().email().required().messages({
                    'string:email': 'Please provide a valid email address'
                }), 
                password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])')).required().messages({
                    'string:min': 'Password must be at least 8 characters long',
                    'string:pattern.base': 'Password must contain uppercase, lowercase, number and special character'
                }), 
                firstName: Joi.string().max(50).required(),
                lastName: Joi.string().max(50).required()
            });

            // Validate the request data
            const { error, value} = schema.validate(req.body, {abortEarly: false});

            if (error){
                return res.status(400).json({
                    success: false, 
                    message: 'Validation failed',
                    errors: error.details.map(detail => detail.message)
                });
            }

            const { username, email, password, firstName, lastName} = value;

            // Check if user already exists
            // Username and Email must be unique for security and UX
            const existingUser = await executeQuery(`
                SELECT UserID FROM Users 
                WHERE Username = @username OR Email = @email
                `, { username, email});

            if(existingUser.recordset.length > 0){
                logger.warn('Registration attempt with existing credentials', {username, email});
                return res.status(409).json({
                    success: false, 
                    message: 'Username or email already exists'
                });
            }

            // Hash Password
            // bcrypt: Slow hashing algorithm resistant to brute force attacks
            // salt rounds 12: Good balance between security and performance

            const saltRounds = 12;
            const passwordHash = await bcrypt.hash(password, saltRounds);

            // Create User in database
            const result = await executeQuery(`
                INSERT INTO Users (Username, Email, PasswordHash, FirstName, LastName, Role, IsActive)
                OUTPUT INSERTED.UserID, INSERTED.Username, INSERTED.Email, INSERTED.FirstName, INSERTED.LastName, INSERTED.Role, INSERTED.IsActive, INSERTED.CreatedAt
                VALUES (@username, @email, @passwordHash, @firstName, @lastName, 'User', 1)
                `, {
                    username, email, passwordHash, firstName, lastName
                });

            const newUser = result.recordset[0];

            // Create session for new user - automatic login after registration
            req.session.userId = newUser.UserID;
            req.session.username = newUser.Username;
            req.session.role = newUser.Role; 

            // Log successful registration for audit purposes
            logger.info('User registered succesfully', {
                userId: newUser.UserID,
                username: newUser.Username,
                email: newUser.Email, 
                registrationTime: newUser.CreatedAt
            });

            // Return success response
            res.status(201).json({
                success: true, 
                message: 'User registered succesfully', 
                data: {
                    userId: newUser.UserID, 
                    username: newUser.Username, 
                    email: newUser.Email, 
                    firstName: newUser.FirstName, 
                    lastName: newUser.LastName,
                    role: newUser.Role
                }
            });

        } catch (error) {
            logger.error('Registration failed', {
                error: error.message, stack: error.stack
            });
            res.status(500).json({
                success: false, 
                message: 'Registration failed. Please try again'
            })
        }
    }

    // User Login Endpoint
    async login (req, res) {
        try {
            const schema = Joi.object({
                username: Joi.string().required().messages({
                    'any.required': 'Username or email is required'
                }),
                password: Joi.string().required().messages({
                    'any.required': 'Password is required'
                }),
                rememberMe: Joi.boolean().optional() // For extended session duration
            });

            const { error, value } = schema.validate(req.body);

            if(error) {
                return res.status(400).json({
                    success: false, 
                    message: error.details[0].message
                });
            }

            const { username, password, rememberMe } = value;

            // Find user by username OR email - flexible login
            const userResult = await executeQuery(`
                SELECT UserID, Username, Email, PasswordHash, FirstName, LastName, Role, IsActive, LastLoginAt
                FROM Users
                WHERE (Username = @username OR Email = @username) AND IsActive = 1
                `, { username });

            if (userResult.recordset.length === 0){
                logger.warn('Login attempt with invalid username', { username, ip: req.ip });
                return res.status(401).json({
                    success: false, 
                    message: 'Invalid username or password'
                });
            }

            const user = userResult.recordset[0];

            //Verify password using bcrypt
            const isValidPassword = await bcrypt.compare(password, user.passwordHash);

            if(!isValidPassword){
                //Log failed login attempt for security monitoring
                logger.warn('Failed login attempt - invalid password', {
                    userId: user.UserID, 
                    username: user.Username,
                    ip: req.ip, 
                    UserAgent: req.get('User-Agent')
                });
            }

            // Update last login time for user tracking
            await executeQuery(`UPDATE Users SET LastLoginAt = GETUTCDATE() WHERE UserID = @userId`, { userId: user.UserID});

            // Create user session
            req.session.userId = user.UserID;
            req.session.username = user.Username;
            req.session.role = user.Role;

            // Set session duration based on Remember Me option
            if (rememberMe){
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
            } else {
                req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 24 hours
            }

            // Log succesful login
            logger.info('User logged in successfully', {
                userId: user.UserID, 
                username: user.Username, 
                ip: req.ip, 
                rememberMe: !!rememberMe
            });

            // Return user information (excluding sensitive data)
            res.json({
                success: true, 
                message: 'Login successful', 
                data: {
                    userId: user.UserID, 
                    username: user.UserID,
                    email: user.Email, 
                    firstName: user.FirstName, 
                    lastName: user.LastName, 
                    role: user.Role, 
                    lastLoginAt: user.LastLoginAt
                }
            });


        } catch (error) {
            logger.error('Login failed', {error: error.message, stack: error.stack});
            res.status(500).json({
                success: false, 
                message: 'Login failed. Please try again.'
            });
        }
    }

    // User Logout Endpoint
    async logout(req, res) {
        try {
            const userId = req.session?.userId;

            // Destroy session to log out user
            req.session.destroy((error) => {
                if (error){
                    logger.error('Session destruction failed', { error: error.message, userId});
                    return res.status(500).json({
                        success: false, 
                        message: 'Logout failed'
                    });
                }

                // Clear the session cookie from client
                res.clearCookie('connect.sid')

                // Log successful logout
                if (userId){
                    logger.info('User logged out successfully', {userId});
                }

                res.json({
                    success: true, 
                    message: 'Logout successful'
                });
            });

        } catch (error) {
            logger.error('Login failed', { error: error.message});
            res.status(500).json({
                success: false, 
                message: 'Logout failed'
            });
        }
    }

    async getCurrentUser (req, res) {
        try {
            // Session middleware should populate req.session
            if(!req.session?.userId){
                return res.status(401).json({
                    success: false, 
                    message: 'Not authenticated'
                });
            }

            // Get user data from database
            const userResult = await executeQuery(`
                SELECT UserID, Username, Email, FirstName, LastName, Role, CreatedAt, LastLoginAt
                FROM Users
                WHERE UserID = @userId AND IsActive = 1
                `, { userId: req.session.userId});

            if(userResult.recordset.length === 0){
                // User was deleted or deactivated - destroy session
                req.session.destroy();
                return res.status(401).json({
                    success: false, 
                    message: 'User account not found'
                });
            }

            const user = userResult.recordset[0];

            res.json({
                success: true,
                data: user
            });

        } catch (error) {
            logger.error('failed to get current user', { error: error.message});
            res.status(500).json({
                success: false, 
                message: 'Failed to get user information'
            });
        }
    }

    // Middleware to require authentication (Re-usable across mutliple routes)
    static requireAuth(req, res, next){
        if (!req.session?.userId){
            return res.status(401).json({
                success: false, 
                message: 'Authentication required'
            });
        }
        next() // Continue to the next middleware/route handler
    }

    // Middleware for role-based access control
    static requireRole(allowRoles){
        return (req, res, next) => {
            if(!req.session?.userId){
                return res.status(401).json({
                    success: false, 
                    message: 'Authentication required'
                });
            }

            if(!allowRoles.includes(req.session.role)){
                logger.warn('Access denied - insufficient privileges', {
                    userId: req.session.userId, 
                    userRole: req.session.role, 
                    requiredRoles: allowRoles, 
                    requestedResource: req.originalUrl
                });

                return res.status(403).json({
                    success: false, 
                    message: 'Insufficient permissions'
                });
            }
            next(); // User has required role, continue
        }       
    }
}

module.exports = new AuthController();


