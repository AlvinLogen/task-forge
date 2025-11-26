// Centralized logging system for debugging and monitoring
const winston = require('winston');
const path = require('path');

const fs = require('fs');
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)){
    fs.mkdirSync(logsDir, {
        recursive: true
    });
}

// Configure winston logger with multiple transports
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info', 
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({
            stack: true
        }),
        winston.format.json()
    ),
    defaultMeta: { service: 'taskforge-api'},
    transports: [
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log' ),
            level: 'error'
        }),
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log')
        }),
    ],
});

// In development environment, log to console
if(process.env.NODE_ENV !== 'production'){
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

module.exports = logger;