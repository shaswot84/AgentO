import { createApp } from './app.js';

const port = Number(process.env.PORT) || 3300;
const app = createApp();

app.listen(port, () => {
  console.log(`Demo App 03 (SSR Portal) listening on http://127.0.0.1:${port}`);
});
