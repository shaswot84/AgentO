import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';
import { attachSessionCookies } from '../middleware/auth.js';

export const authRouter = Router();

authRouter.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = db.prepare('SELECT id, username, password, role, email, full_name FROM users WHERE username = ?').get(username) as any;

  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const sessionUser = {
    id: user.id,
    username: user.username,
    role: user.role,
    email: user.email,
    fullName: user.full_name
  };

  req.session.user = sessionUser;

  // Generate session token and attach cookies (demonstrating CWE-1004 & CWE-614)
  const token = `sess_${user.username}_${Buffer.from(String(user.id) + ':' + Date.now()).toString('base64')}`;
  attachSessionCookies(req, res, token);

  return res.json({
    message: 'Login successful',
    user: sessionUser,
    sessionToken: token
  });
});

authRouter.post('/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to logout' });
    }
    res.clearCookie('auth_token');
    res.clearCookie('connect.sid');
    return res.json({ message: 'Logged out successfully' });
  });
});

authRouter.get('/me', (req: Request, res: Response) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ authenticated: false, user: null });
  }
  return res.json({
    authenticated: true,
    user: req.session.user
  });
});
