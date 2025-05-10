import express, { Express, Request, Response, NextFunction } from 'express';
import session from 'express-session';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { networkInterfaces } from 'os';
import { resolve } from 'path';
import { registerRoutes } from './routes';
import { setupVite, serveStatic, log } from './vite';
import { initializeModel } from './ml/model_handler';
import { networkAnalyzer } from './network/analyzer';

// Create Express instance
const app: Express = express();

// Parse JSON bodies
app.use(express.json());

// Session middleware
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'network-intrusion-detection-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
});

app.use(sessionMiddleware);

// Create HTTP server
const httpServer = createServer(app);

// Print local addresses for convenience
const getNetworkAddresses = () => {
  const interfaces = networkInterfaces();
  const addresses: string[] = [];

  Object.values(interfaces).forEach((iface) => {
    if (!iface) return;
    iface.forEach((details) => {
      if (details.family === 'IPv4' && !details.internal) {
        addresses.push(details.address);
      }
    });
  });

  return addresses;
};

// Initialize and setup server
async function init() {
  try {
    // Initialize ML model
    await initializeModel();
    
    // Register API routes and create WebSocket server
    await registerRoutes(app);
    
    // Start the network analyzer
    networkAnalyzer.start();
    
    // Setup Vite for development or static file serving for production
    if (process.env.NODE_ENV === 'development') {
      await setupVite(app, httpServer);
    } else {
      serveStatic(app);
    }
    
    // Error handler
    app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
      console.error(err);
      res.status(err.status || 500).json({
        message: err.message,
        error: process.env.NODE_ENV === 'development' ? err : {}
      });
    });
    
    // Start server
    const PORT = process.env.PORT || 5000;
    httpServer.listen(PORT, '0.0.0.0', () => {
      log(`serving on port ${PORT}`);
      const addresses = getNetworkAddresses();
      if (addresses.length > 0) {
        addresses.forEach((address) => {
          log(`Network access: http://${address}:${PORT}`);
        });
      }
    });
  } catch (error) {
    console.error('Failed to initialize server:', error);
    process.exit(1);
  }
}

// Start the server
init();

// Handle graceful shutdown
process.on('SIGINT', () => {
  log('Shutting down server...');
  networkAnalyzer.stop();
  process.exit(0);
});
