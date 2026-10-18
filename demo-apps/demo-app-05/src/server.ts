import { createApp } from './app.js';

const port = Number(process.env.PORT ?? 3005);
const app = createApp();

app.listen(port, () => {
  console.log(`Demo App 05 (Cloud Ops Console) listening at http://localhost:${port}`);
});
