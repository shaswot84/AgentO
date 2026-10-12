import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';
import { requireAdmin } from '../middleware/auth.js';
import { isFixedMode } from '../config.js';

export const adminRouter = Router();

/**
 * GET /api/admin/users
 * Demonstrates CWE-862 (Missing Authorization)
 */
adminRouter.get('/users', requireAdmin, (req: Request, res: Response) => {
  const fixed = isFixedMode(req);
  const currentUser = req.session?.user;

  const users = db.prepare('SELECT id, username, role, email, full_name FROM users').all();

  return res.json({
    securityMode: fixed ? 'fixed' : 'vulnerable',
    cwe: fixed ? 'CWE-862 Fixed (Admin role enforced)' : 'CWE-862 Vulnerable (Missing Authorization: customer accessed admin API)',
    accessedBy: currentUser?.username,
    userRole: currentUser?.role,
    users
  });
});

/**
 * GET /api/admin/stats
 * Administrative metrics
 */
adminRouter.get('/stats', requireAdmin, (req: Request, res: Response) => {
  const fixed = isFixedMode(req);
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get() as any;
  const orderCount = db.prepare('SELECT COUNT(*) as count, SUM(total_price) as revenue FROM orders').get() as any;
  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get() as any;

  return res.json({
    securityMode: fixed ? 'fixed' : 'vulnerable',
    stats: {
      totalUsers: userCount.count,
      totalOrders: orderCount.count,
      totalRevenue: orderCount.revenue,
      totalProducts: productCount.count
    }
  });
});

/**
 * DELETE /api/admin/users/:id
 * Delete a user
 */
adminRouter.delete('/users/:id', requireAdmin, (req: Request, res: Response) => {
  const targetId = parseInt(req.params.id as string, 10);
  if (isNaN(targetId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  // Prevent deleting admin
  if (targetId === 3) {
    return res.status(400).json({ error: 'Cannot delete primary admin account' });
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(targetId);

  return res.json({
    message: `User ${targetId} successfully deleted`
  });
});
