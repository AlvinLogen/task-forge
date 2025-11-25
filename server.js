// Require Installed Packages
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const path = require('path');

require('dotenv').config();

// Require Project Files and Dependancies
const logger = require('./backend/src/utils/logger');
const { connectDB} = require('./backend/src/utils/database');
const errorHandler = require('./backend/src/middleware/errorHandler');
const authRoutes = require('./backend/src/routes/projects');
const projectRoutes = require('./backend/src/routes/tasks');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "'data:'", "'https:'"]
        }
    }
}));

//Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per winowsMs
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,

});

// CORS Configuration
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:300',
    credentials: true
}));

// Compression and Parsing
app.use(compression());
app.use(express.json({ limit: '10mb'}));
app.use(express.urlencoded({ extended: true, limit: '10mb'}));

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false, 
    saveUninitialized: false, 
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true, 
        maxAge: 24 * 60 * 60 * 1000 // Cookie expires after 24 hours
    }
}));

// Serve Static Files
app.use(express.static(path.join(__dirname, 'frontend')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/tasks', taskRoutes);

//Health Check Endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

//Serve Frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Error handling Middleware
app.use(errorHandler);

// Start Server
async function startServer() {
    try{
        await connectDB();
        app.listen(PORT, () => {
            logger.info(`TaskForge API server running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`)
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

//  Handle graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on("SIGINT", () => {
    logger.info('SIGINT received shutting down gracefully');
    process.exit(0);
}); 

startServer();

module.exports = app;

