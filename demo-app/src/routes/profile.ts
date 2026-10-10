import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';

export const profileRouter = Router();

profileRouter.get('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.session.user!.id;
  const user = db.prepare('SELECT id, username, role, email, full_name FROM users WHERE id = ?').get(userId) as any;

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  return res.json({
    id: user.id,
    username: user.username,
    role: user.role,
    email: user.email,
    fullName: user.full_name
  });
});

profileRouter.put('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.session.user!.id;
  const { email, fullName } = req.body;

  if (!email || !fullName) {
    return res.status(400).json({ error: 'Email and fullName are required' });
  }

  db.prepare('UPDATE users SET email = ?, full_name = ? WHERE id = ?').run(email, fullName, userId);

  // Update session
  req.session.user!.email = email;
  req.session.user!.fullName = fullName;

  return res.json({
    message: 'Profile updated successfully',
    user: req.session.user
  });
});
