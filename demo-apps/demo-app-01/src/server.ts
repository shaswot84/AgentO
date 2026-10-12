import { createApp } from './app.js';
import { initDatabase } from './db/database.js';
import { getSecurityMode } from './config.js';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Initialize SQLite database and seed test accounts (Alice, Bob, Admin)
initDatabase();

const app = createApp();

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  AgentO Vulnerable Demo Application (Phase 1)`);
  console.log(`=======================================================`);
  console.log(`Server running at:       http://localhost:${PORT}`);
  console.log(`Active Security Mode:    ${getSecurityMode().toUpperCase()}`);
  console.log(`Test Users Seeded:`);
  console.log(`  - Alice (Customer):     username: alice  / password: alice123`);
  console.log(`  - Bob   (Customer):     username: bob    / password: bob123`);
  console.log(`  - Admin (Privileged):   username: admin  / password: admin123`);
  console.log(`=======================================================`);
});
