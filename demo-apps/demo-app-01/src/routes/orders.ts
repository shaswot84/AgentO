import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';
import { isFixedMode } from '../config.js';

export const ordersRouter = Router();

/**
 * GET /api/orders
 * Returns orders belonging to current user (or all if admin)
 */
ordersRouter.get('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.session.user!.id;
  const role = req.session.user!.role;

  if (role === 'admin') {
    const allOrders = db.prepare(`
      SELECT o.*, u.username as customer_username
      FROM orders o
      JOIN users u ON o.user_id = u.id
      ORDER BY o.id DESC
    `).all();
    return res.json(allOrders);
  }

  const userOrders = db.prepare(`
    SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC
  `).all(userId);

  return res.json(userOrders);
});

/**
 * POST /api/orders
 * Place a new order
 */
ordersRouter.post('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.session.user!.id;
  const { productName, quantity, totalPrice, shippingAddress } = req.body;

  if (!productName || !quantity || !totalPrice || !shippingAddress) {
    return res.status(400).json({ error: 'Missing required order fields' });
  }

  const insert = db.prepare(`
    INSERT INTO orders (user_id, product_name, quantity, total_price, shipping_address)
    VALUES (?, ?, ?, ?, ?)
  `);

  const result = insert.run(userId, productName, Number(quantity), Number(totalPrice), shippingAddress);

  return res.status(201).json({
    message: 'Order placed successfully',
    orderId: result.lastInsertRowid
  });
});

/**
 * GET /api/orders/:id
 * Demonstrates CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR)
 */
ordersRouter.get('/:id', requireAuth, (req: Request, res: Response) => {
  const orderId = parseInt(req.params.id as string, 10);
  if (isNaN(orderId)) {
    return res.status(400).json({ error: 'Invalid order ID' });
  }

  const order = db.prepare(`
    SELECT o.*, u.username as owner_username, u.email as owner_email
    FROM orders o
    JOIN users u ON o.user_id = u.id
    WHERE o.id = ?
  `).get(orderId) as any;

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  const currentUserId = req.session.user!.id;
  const currentUserRole = req.session.user!.role;
  const fixed = isFixedMode(req);

  if (fixed) {
    // FIXED (CWE-639): Strictly enforce object-level authorization (ownership check)
    const isOwner = order.user_id === currentUserId;
    const isAdmin = currentUserRole === 'admin';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Access denied: You are not authorized to view this order',
        securityMode: 'fixed',
        cwe: 'CWE-639 Fixed (Ownership verified)'
      });
    }

    return res.json({
      securityMode: 'fixed',
      order
    });
  } else {
    // VULNERABLE (CWE-639): Direct object reference without verifying ownership
    // Any authenticated user can view any other user's order details simply by modifying the ID parameter
    return res.json({
      securityMode: 'vulnerable',
      cwe: 'CWE-639 Vulnerable (IDOR: User ownership check omitted)',
      order,
      warning: order.user_id !== currentUserId ? `IDOR EXPLOIT: User ${req.session.user!.username} accessed order owned by ${order.owner_username}` : undefined
    });
  }
});
