import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';

export const productsRouter = Router();

productsRouter.get('/', (req: Request, res: Response) => {
  const category = req.query.category as string | undefined;

  if (category) {
    const products = db.prepare('SELECT * FROM products WHERE category = ?').all(category);
    return res.json(products);
  }

  const products = db.prepare('SELECT * FROM products').all();
  return res.json(products);
});

productsRouter.get('/:id', (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }

  return res.json(product);
});
