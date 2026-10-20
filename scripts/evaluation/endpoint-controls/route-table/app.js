import express from 'express';
const auth = express.Router();
auth.post('/login', (req, res) => res.json({ email: req.body.email }));
const root = express.Router();
const routes = [{ path: '/auth', route: auth }];
routes.forEach((entry) => root.use(entry.path, entry.route));
const app = express();
app.use('/v1', root);
export default app;
