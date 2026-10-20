import express from 'express';
const app = express();
function register(target) {
  target.get('/registered', (req, res) => res.json({ value: req.query.value }));
}
register(app);
export default app;
