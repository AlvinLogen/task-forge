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
