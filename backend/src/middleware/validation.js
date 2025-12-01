// Centralized input validation and sanitization
// Prevention: Data sanitization, SQL injection prevention, XSS prevention

const Joi = require("joi");
const DOMPurify = require("isomorphic-dompurify");
const logger = require("../utils/logger");

// Common validation schemas
const validationSchema = {
  //User registration schema
  userRegistration: Joi.object({
    username: Joi.string().alphanum().min(3).max(50).required().messages({
      "string.alphanum": "Username must contain only letters and numbers",
      "string.min": "Username must be at least 3 characters long",
      "string.max": "username must not exceed 50 characters",
      "any.required": "Username is required",
    }),
    email: Joi.string().email().max(100).required().messages({
      "string.email": "Please provide a valid email address",
      "any.required": "Email is required",
    }),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(
        new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])")
      )
      .required()
      .messages({
        "string.min": "Password must be at least 8 characters long",
        "string.max": "Password must not exceed 128 characters",
        "string.pattern.base":
          "Password must contain uppercase, lowercase, number, and special characters",
        "any.required": "Password is required",
      }),
    firstName: Joi.string()
      .max(50)
      .pattern(new RegExp("^[a-zA-Z\\s]+$"))
      .required()
      .messages({
        "string.pattern.base":
          "First name must contain only letters and spaces",
        "any.required": "First name is required",
      }),
    lastName: Joi.string()
      .max(50)
      .pattern(new RegExp("^[a-zA-Z\\s]+$"))
      .required()
      .messages({
        "string.pattern.base": "Last name must contain only letters and spaces",
        "any.required": "Last name is required",
      }),
  }),

  // User Login Validation
  userLogin: Joi.object({
    username: Joi.string().required().messages({
        'any.required': 'Username or email is required'
    }), 
    password: Joi.string().required().messages({
        'any.required': 'Password is required'
    }), 
    rememberMe: Joi.boolean().optional(0)
  }), 

// Project Creation Schema
  projectCreation: Joi.object({
    projectName: Joi.string().min(1).max(100).required().messages({
        'string.min': 'Project name cannot be empty', 
        'string.max': 'Project name must not exceed 100 characters', 
        'any.required': 'Project name is required'
    }), 
    description: Joi.string().max(500).optional().allow('').messages({
        'string.max': 'Description must not exceed 500 characters'
    }), 
    priority: Joi.string().valid('Low', 'Medium', 'High', 'Critical').default('Medium').messages({
        'any.only': 'Priority must be Low, Medium, High or Critical'
    }), 
    startDate: Joi.date().optional().allow(null), 
    endDate: Joi.date().optional().allow(null).when('startDate', {
        is: Joi.exist(),
        then: Joi.date().min(Joi.ref('startDate')), 
        otherwise: Joi.optional()
    }).messages({
        'date.min': 'End date must be after start date'
    }), 
  }), 

  // Task Creation Schema
  taskCreation: Joi.object({
    taskName: Joi.string().min(1).max(200).required().messages({
        'string.min': 'Task name cannot be empty', 
        'string.max': 'Task name must not exceed 200 characters', 
        'any.required': 'Task name is required'
    }), 
    description: Joi.string().max(1000).optional().allow('').messages({
        'string.max': 'Description must not exceed 1000 characters'
    }), 
    projectId: Joi.number().integer().positive().required().messages({
        'number.integer': 'Project ID must be a valid number', 
        'number.positive': 'Project ID must be positive', 
        'any.required': 'Project ID is required'
    }), 
    assignedToId: Joi.number().integer().positive().optional().allow(null).messages({
        'number.integer': 'Assigned user ID must be a valid number', 
        'number.positive': 'Assigned user ID must be positive'
    }), 
    priority: Joi.string().valid('Low', 'Medium', 'High', 'Critical').default('Medium').messages({
        'any.only': 'Priority must be Low, Medium, High or Critical'
    }), 
    estimatedHours: Joi.number().positive().max(999.99).optional().allow(null).messages({
        'number.positive': 'Estimated Hours must be positive', 
        'number.max': 'Estimated Hours must not exceed 999.99'
    }), 
    dueDate: Joi.date().optional().allow(null)
  })
};

// Generic validation middleware factory: middleware for different validation schemas
const validateRequest = (schema, property = 'body') => {
    return (req, res, next) => {
        // Get data based on property (body, query, params)
        const dataToValidate = req[property]; 

        // Validate data against the schema
        const { error, value } = schema.validate(dataToValidate, {
            abortEarly: false, 
            stripUnknown: true
        }); 

        if (error){
            logger.warn('Validation failed', {
                property, 
                errors: error.details.map(detail => detail.message), 
                userId: req.session?.userId, 
                ip: req.ip, 
                userAgent: req.get('User-Agent')
            });

            return res.status(400).json({
                success: false, 
                message: 'Validation failed', 
                errors: error.details.map(detail => detail.message)
            });
        }

        // Replace request data with validated and sanitized data
        req[property] = value;
        next();
    }
};

// Input santization middleware: Prevent XSS attacks and malformed data
const sanitizeInput = (req, res, next) => {
    // Recursive function to santize all string values
    const sanitizeValue = (value) => {
        if(typeof value === 'string'){
            // Remove HTML tags and scripts
            let sanitized = DOMPurify.sanitize(value, { ALLOWED_TAGS: []});

            // Trim whitespace
            sanitized = sanitized.trim();

            // Remove null bytes (can cause issues with databases)
            sanitized = sanitized.replace(/\0/g, '');

            return sanitized;
        } else if (Array.isArray(value)) {
            return value.map(sanitizeValue);
        } else if (value && typeof value === 'object') {
            const santizedObj = {}; 
            for (const key in value){
                santizedObj[key] = sanitizeValue(value[key]);
            }
            return santizedObj
        }
        return value; 
    };

    // Santize request body, query, and params
    if (req.body){
        req.body = sanitizeValue(req.body);
    }

    if (req.query){
        req.query = sanitizeValue(req.query);
    }

    if (req.params) {
        req.params = sanitizeValue(req.params);
    }

    next();
};

// SQL injection prevention helper
const preventSQLInjection = (req, res, next) => {
    const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
        /(UNION|OR|AND)\s+\d+\s*=\s*\d+/i,
        /['"]\s*(OR|AND)\s+['"]\d+['"]\s*=\s*['"]\d+['"]/i,
        /['"]\s*;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i
    ];

    const checkForSQL = (value) => {
        if (typeof value === 'string') {
            return sqlPatterns.some(pattern => pattern.test(value));
        } else if (Array.isArray(value)){
            return value.some(checkForSQL);
        } else if (value && typeof value === 'object'){
            return Object.values(value).some(checkForSQL);
        }
        return false;
    };

    // Check all request data for SL injection pattersn
    if(checkForSQL(req.body) || checkForSQL(req.query) || checkForSQL(req.params)){
        logger.warn('Potential SQL injection attempt detected', {
            userId: req.session?.userId,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.originalUrl,
            body: req.body,
            query: req.query,
            params: req.params
        });

        return res.status(400).json({
            success: false, 
            message: 'Invalid input detected'
        });
    }

    next();
};

// Rate limiting per user (in addition to global rate limiting)
const userRateLimit = new Map();

const limitUserRequests = (maxRequests = 60, windowMs = 60000) => {
    return (req, res, next) => {
        const userId = req.session?.userId;
        if (!userId) {
            return next(); // Skip rate limiting for unauthenticated users (global limit applies)
        }

        const now = Date.now();
        const userKey = `user_${userId}`;
        
        if (!userRateLimit.has(userKey)) {
            userRateLimit.set(userKey, { requests: 1, resetTime: now + windowMs });
            return next();
        }

        const userLimit = userRateLimit.get(userKey);
        
        if (now > userLimit.resetTime) {
            // Reset the counter
            userLimit.requests = 1;
            userLimit.resetTime = now + windowMs;
            return next();
        }

        if (userLimit.requests >= maxRequests) {
            logger.warn('User rate limit exceeded', {
                userId,
                requests: userLimit.requests,
                limit: maxRequests
            });

            return res.status(429).json({
                success: false,
                message: 'Too many requests. Please slow down.'
            });
        }

        userLimit.requests++;
        next();
    };   
};

module.exports = {
    //Validation scehams
    schemas: validationSchema, 

    //Validation middleware
    validateUserRegistration: validateRequest(validationSchema.userRegistration), 
    validateUserLogin: validateRequest(validationSchema.userLogin), 
    validateProjectCreation: validateRequest(validationSchema.projectCreation),
    validateTaskCreation: validateRequest(validationSchema.taskCreation),

    //Generic Validation
    validateRequest, 

    //Security Middleware
    sanitizeInput, 
    preventSQLInjection, 
    limitUserRequests
};
