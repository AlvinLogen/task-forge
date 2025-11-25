//Centralized database connection and query management
const sql = require('mssql');
const logger = require('./logger');

// Database configuration object
const dbConfig = {
    user: process.env.DB_USER || 'sa',
    password: process.env.DB_PASSWORD, 
    server: process.env.DB_SERVER || 'localhost',
    database: process.env.DB_NAME || 'TaskForge',
    options: {
        encrypt: false, 
        trustServerCertificate: true,
        enableArithAbort: true, 
        requestTimeout: 30000, 
    }, 
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000,
    },
};

let poolPromise;

// Establish database connection with connection pooling
const connectDB = async () => {
    try {
        poolPromise = sql.connect(dbConfig);
        await poolPromise;
        logger.info('Connected to SQL Server database');
        return poolPromise;
    } catch (error) {
        logger.error('Database connection failed:', error);
        throw error;
    }
};

// Get the connection pool instanc
const getPool = () => {
    if (!poolPromise) {
        throw new Error('Database not connected. Call connectDb first.');
    }
    return poolPromise;
};

// Execute SQL queries with parameterized inputs
const executeQuery = async (query, parameters = {}) => {
  try {
    const pool = await getPool();
    const request = pool.request();

    // Each parameter escaped and typed
    Object.keys(parameters).forEach(key => {
        request.input(key, parameters[key])
    });

     // query with parameters safely embedded
    const result = await request.query(query);

    if (process.env.NODE_ENV === 'development'){
        logger.debug('Query executed successfully', {query, parameters});
    }

    return result

  } catch (error) {
    logger.error('Query execution failed:', {error:error.message, query, parameters});
    throw error;
  }  
};

// Execute Parameterized Store Procedure
const executeProcedure = async (procedureName, parameters = {}) => {
    try {
        const pool = await getPool();
        const request = pool.request();
        
        // Each parameter escaped and typed
        Object.keys(parameters).forEach(key => {
            request.input(key, parameters[key])
        });

        const result = await request.execute(procedureName);

        return result;
    } catch (error) {
        logger.error('Procedure execution failed:', { error: error.message, procedureName, parameters });
        throw error;
    }
};

// Graceful database disconnection
const disconnectDB = async () => {
    try {
        if (poolPromise) {
            await sql.close();
            logger.info('Database connection closed');
        }
    } catch (error) {
        logger.error('Error closing database connection:', error);
    }
};

module.exports = {
    connectDB,
    getPool,
    executeQuery,
    executeProcedure,
    disconnectDB,
    sql 
};

