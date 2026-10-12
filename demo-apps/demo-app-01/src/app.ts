import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';

import { corsMiddleware } from './middleware/cors.js';
import { isFixedMode } from './config.js';
import { authRouter } from './routes/auth.js';
import { profileRouter } from './routes/profile.js';
import { productsRouter } from './routes/products.js';
import { ordersRouter } from './routes/orders.js';
import { adminRouter } from './routes/admin.js';
import { searchRouter } from './routes/search.js';
import { configRouter } from './routes/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp() {
  const app = express();

  // Permissive / Fixed CORS middleware (CWE-942)
  app.use(corsMiddleware);

  // Body parsers & Cookie parser
  app.use(cookieParser());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Session middleware instantiated once to preserve session store across requests
  const sessionMiddleware = session({
    name: 'agento_sid',
    secret: 'agento-super-secret-demo-session-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      secure: false,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    }
  });

  app.use(sessionMiddleware);

  // Dynamic session cookie attributes per security mode
  app.use((req, res, next) => {
    const fixed = isFixedMode(req);
    if (req.session && req.session.cookie) {
      req.session.cookie.httpOnly = fixed;
      req.session.cookie.secure = fixed && (req.secure || process.env.COOKIE_SECURE === 'true');
    }
    next();
  });

  // Serve static UI assets
  app.use(express.static(path.resolve(__dirname, '../public')));

  // Mount API routers
  app.use('/api/auth', authRouter);
  app.use('/api/profile', profileRouter);
  app.use('/api/products', productsRouter);
  app.use('/api/orders', ordersRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api/config', configRouter);

  // Mount Search router (contains /search HTML and /api/search)
  app.use('/', searchRouter);

  // Direct route for /admin page
  app.get('/admin', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../public/admin.html'));
  });

  return app;
}
