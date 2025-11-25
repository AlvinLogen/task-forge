# TaskForge - Task Management System

Enterprise-grade task management system built with Node.js, Express, and SQL Server.

## Prerequisites

- Node.js 18+ 
- SQL Server
- npm or yarn

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
3. Configure environment variables:
    Copy .env.example to .env
    Update database credentials and session secret
4. Create database: npm run db:setup
5. Start development server: npm run dev
6. Available Scripts
    npm start - Start production server
    npm run dev - Start development server with auto-reload
    npm test - Run tests
    npm run lint - Check code quality
    npm run format - Format code

### Technology Stack

**Frontend Stack**:
```
├── HTML5 semantic structure           // Proper document structure for accessibility and SEO
├── CSS Grid + Flexbox layouts        // Modern layout techniques for responsive design
├── Vanilla JavaScript (ES6+)         // Core language features without framework complexity
├── Fetch API for HTTP requests       // Modern way to communicate with backend APIs
├── CSS custom properties (variables) // Maintainable styling system
└── Progressive enhancement approach   // Ensure functionality works without JavaScript
```

**Backend Stack**:
```
├── Node.js runtime environment       // JavaScript server-side execution
├── Express.js web framework          // Minimal, flexible web application framework
├── Express session management        // Server-side session storage for authentication
├── Helmet.js for security headers    // Security middleware for Express applications
├── Express rate limiting             // Prevent abuse and DoS attacks
├── Winston for logging               // Professional logging library for debugging
└── Joi for input validation          // Schema validation for user input
```

**Database Stack**:
```
├── SQL Server with T-SQL             // Relational database with powerful query language
├── Connection pooling (mssql package)// Efficient database connection management
├── Parameterized queries            // Prevent SQL injection attacks
├── Basic indexing strategy          // Improve query performance
├── Transaction support             // Ensure data consistency
└── Database constraints            // Enforce data integrity at database level
```

**Development Tools**:
```
├── Jest for unit testing            // JavaScript testing framework
├── Supertest for API testing       // HTTP assertion library for Node.js
├── ESLint for code quality         // Static analysis tool for JavaScript
├── Prettier for code formatting   // Automatic code formatting
├── Nodemon for development        // Auto-restart server during development
└── Git for version control       // Track changes and collaborate
```

## Project Structure
``` 
taskforge/
├── backend/
│   ├── src/           # Source code
│   ├── tests/         # Test files
│   ├── database/      # SQL scripts
│   └── scripts/       # Utility scripts
├── frontend/          # Frontend assets
└── [server.js](http://_vscodecontentref_/8)          # Application entry point
```
