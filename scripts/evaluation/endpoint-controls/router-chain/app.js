import express, { Router } from 'express';
const users = Router();
users.get('/users', (req, res) => res.json({ q: req.query.q }));
const api = Router().use(users);
const routes = Router().use('/api', api);
const app = express();
app.use(routes);
export default app;
