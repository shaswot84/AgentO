import type { DiscoveryResult } from '@agento/discovery';

// Saved output from discoverProject('demo-app'); no browser filesystem access.
export const demoDiscovery: DiscoveryResult = {
  "repositoryPath": "demo-app",
  "name": "demo-app",
  "languages": [
    "javascript",
    "typescript"
  ],
  "frameworks": [
    "express"
  ],
  "dependencies": [
    {
      "name": "better-sqlite3",
      "version": "^13.0.3",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "cookie-parser",
      "version": "^1.4.7",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "cors",
      "version": "^2.8.6",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "dotenv",
      "version": "^18.0.7",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "express",
      "version": "^5.3.0",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "express-session",
      "version": "^1.19.0",
      "kind": "dependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/better-sqlite3",
      "version": "^9.6.0",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/cookie-parser",
      "version": "^1.4.10",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/cors",
      "version": "^2.8.19",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/express",
      "version": "^5.0.6",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/express-session",
      "version": "^1.19.0",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/node",
      "version": "^26.6.5",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "@types/supertest",
      "version": "^7.2.1",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "supertest",
      "version": "^7.3.1",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "tsx",
      "version": "^4.23.15",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "typescript",
      "version": "^7.0.2",
      "kind": "devDependencies",
      "manifest": "package.json"
    },
    {
      "name": "vitest",
      "version": "^5.0.3",
      "kind": "devDependencies",
      "manifest": "package.json"
    }
  ],
  "databases": [
    "sqlite"
  ],
  "orms": [],
  "authentication": [
    "session"
  ],
  "authenticationPackages": [
    "express-session"
  ],
  "middleware": [
    {
      "kind": "cookie",
      "name": "cookie-parser",
      "file": "package.json",
      "basis": "dependency"
    },
    {
      "kind": "cors",
      "name": "cors",
      "file": "package.json",
      "basis": "dependency"
    },
    {
      "kind": "session",
      "name": "express-session",
      "file": "package.json",
      "basis": "dependency"
    },
    {
      "kind": "session",
      "name": "express-session",
      "file": "src/app.ts",
      "basis": "import",
      "line": 2
    },
    {
      "kind": "cookie",
      "name": "cookie-parser",
      "file": "src/app.ts",
      "basis": "import",
      "line": 3
    },
    {
      "kind": "cors",
      "name": "custom-cors",
      "file": "src/middleware/cors.ts",
      "basis": "header",
      "line": 16
    },
    {
      "kind": "cors",
      "name": "custom-cors",
      "file": "src/middleware/cors.ts",
      "basis": "header",
      "line": 20
    },
    {
      "kind": "cors",
      "name": "custom-cors",
      "file": "src/middleware/cors.ts",
      "basis": "header",
      "line": 25
    },
    {
      "kind": "cors",
      "name": "custom-cors",
      "file": "src/middleware/cors.ts",
      "basis": "header",
      "line": 28
    },
    {
      "kind": "session",
      "name": "express-session",
      "file": "src/types.ts",
      "basis": "import",
      "line": 1
    }
  ],
  "structure": {
    "manifests": [
      {
        "file": "package.json",
        "directory": ".",
        "name": "demo-app",
        "workspacePatterns": []
      }
    ],
    "directories": [
      "public",
      "public/css",
      "public/js",
      "src",
      "src/db",
      "src/middleware",
      "src/routes",
      "test"
    ],
    "sourceDirectories": [
      "src"
    ],
    "testDirectories": [
      "test"
    ],
    "staticDirectories": [
      "public"
    ],
    "sourceFileCount": 16
  },
  "expressAdapterAvailable": false,
  "availableAdapterIds": [],
  "supportedCodeAwareMode": false,
  "mode": "black-box",
  "fallbackReasons": [
    "No Express framework adapter is registered."
  ],
  "diagnostics": []
};
