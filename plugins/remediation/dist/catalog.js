import { freeze } from './value.js';
/** Reviewed source revisions for the controlled Express storefront. No runtime file reads. */
export const recipes = freeze([
    {
        "id": "express-storefront-cwe-89",
        "cweId": "CWE-89",
        "endpoint": "/api/search",
        "explanation": "The search handler interpolates request text into SQL. Bind both LIKE values to prepared-statement placeholders. This keeps the query structure fixed and preserves ordinary product searches.",
        "files": [
            {
                "path": "src/routes/search.ts",
                "sha256": "01950c1eae54eb08d6e95a8c4f935985c775a589e745d1fb164dad49668ca48b",
                "edits": [
                    {
                        "before": "    if (fixed) {\n      // FIXED (CWE-89): Safe parameterized query using prepared statements\n      const stmt = db.prepare(`\n        SELECT id, name, description, category, price, in_stock\n        FROM products\n        WHERE name LIKE ? OR description LIKE ?\n      `);\n      const pattern = `%${q}%`;\n      const results = stmt.all(pattern, pattern);\n\n      return res.json({\n        securityMode: 'fixed',\n        cwe: 'CWE-89 Fixed (Parameterized Query)',\n        query: escapeHtml(q),\n        results\n      });\n    } else {\n      // VULNERABLE (CWE-89): Raw SQL string concatenation\n      // Example payload: ' UNION SELECT id, username, password, role, email, full_name FROM users --\n      const queryStr = `\n        SELECT id, name, description, category, price, in_stock\n        FROM products\n        WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'\n      `;\n      const results = db.prepare(queryStr).all();\n\n      return res.json({\n        securityMode: 'vulnerable',\n        cwe: 'CWE-89 Vulnerable (Raw SQL Concatenation)',\n        query: q,\n        rawExecutedQuery: queryStr,\n        results\n      });\n    }\n",
                        "after": "    // FIXED (CWE-89): Safe parameterized query using prepared statements\n    const stmt = db.prepare(`\n      SELECT id, name, description, category, price, in_stock\n      FROM products\n      WHERE name LIKE ? OR description LIKE ?\n    `);\n    const pattern = `%${q}%`;\n    const results = stmt.all(pattern, pattern);\n\n    return res.json({\n      securityMode: 'fixed',\n      cwe: 'CWE-89 Fixed (Parameterized Query)',\n      query: escapeHtml(q),\n      results\n    });\n\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-79",
        "cweId": "CWE-79",
        "endpoint": "/search",
        "explanation": "The search handler places untrusted query text into an HTML text node. Apply the existing five-character HTML encoder before rendering that text. This recipe is limited to HTML text content; attribute, URL, script, and CSS contexts need different defenses.",
        "files": [
            {
                "path": "src/routes/search.ts",
                "sha256": "01950c1eae54eb08d6e95a8c4f935985c775a589e745d1fb164dad49668ca48b",
                "edits": [
                    {
                        "before": "  let searchDisplay = q;\n  if (fixed) {\n    // FIXED (CWE-79): Escapes all HTML characters before embedding in HTML\n    searchDisplay = escapeHtml(q);\n  } else {\n    // VULNERABLE (CWE-79): User query directly reflected in HTML without escaping\n    // Example payload: <script>alert('XSS')</script> or <img src=x onerror=\"alert('CWE-79')\">\n    searchDisplay = q;\n  }\n",
                        "after": "  const searchDisplay = escapeHtml(q);\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-639",
        "cweId": "CWE-639",
        "endpoint": "/api/orders/:id",
        "explanation": "The order lookup accepts a caller-selected key and returns another user's order when the demo mode bypasses ownership checks. Enforce the existing owner-or-administrator policy before every response. Preserve owner and administrator access and reject other users.",
        "files": [
            {
                "path": "src/routes/orders.ts",
                "sha256": "c3e3e284b4ea331423da9b3b8537db62e10c0029215b08ece8108b563504e2b9",
                "edits": [
                    {
                        "before": "  if (fixed) {\n    // FIXED (CWE-639): Strictly enforce object-level authorization (ownership check)\n    const isOwner = order.user_id === currentUserId;\n    const isAdmin = currentUserRole === 'admin';\n\n    if (!isOwner && !isAdmin) {\n      return res.status(403).json({\n        error: 'Forbidden',\n        message: 'Access denied: You are not authorized to view this order',\n        securityMode: 'fixed',\n        cwe: 'CWE-639 Fixed (Ownership verified)'\n      });\n    }\n\n    return res.json({\n      securityMode: 'fixed',\n      order\n    });\n  } else {\n    // VULNERABLE (CWE-639): Direct object reference without verifying ownership\n    // Any authenticated user can view any other user's order details simply by modifying the ID parameter\n    return res.json({\n      securityMode: 'vulnerable',\n      cwe: 'CWE-639 Vulnerable (IDOR: User ownership check omitted)',\n      order,\n      warning: order.user_id !== currentUserId ? `IDOR EXPLOIT: User ${req.session.user!.username} accessed order owned by ${order.owner_username}` : undefined\n    });\n  }\n",
                        "after": "  // FIXED (CWE-639): Strictly enforce object-level authorization (ownership check)\n  const isOwner = order.user_id === currentUserId;\n  const isAdmin = currentUserRole === 'admin';\n\n  if (!isOwner && !isAdmin) {\n    return res.status(403).json({\n      error: 'Forbidden',\n      message: 'Access denied: You are not authorized to view this order',\n      securityMode: 'fixed',\n      cwe: 'CWE-639 Fixed (Ownership verified)'\n    });\n  }\n\n  return res.json({\n    securityMode: 'fixed',\n    order\n  });\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-862",
        "cweId": "CWE-862",
        "endpoint": "/api/admin/users",
        "explanation": "The administrative middleware authenticates users but allows customers through its demo bypass. Require the administrator role after authentication on every call. The existing administrative routes keep using the same middleware.",
        "files": [
            {
                "path": "src/middleware/auth.ts",
                "sha256": "34b29b0f350fed8f2d1c572fbc0eeb5b42b71e78ef77f76e2451f7aa2fbbe6f3",
                "edits": [
                    {
                        "before": "  const fixed = isFixedMode(req);\n\n  if (fixed) {\n    // FIXED: Enforce role-based access control\n    if (req.session.user.role !== 'admin') {\n      return res.status(403).json({\n        error: 'Forbidden',\n        message: 'Administrator privilege required.'\n      });\n    }\n    next();\n  } else {\n    // VULNERABLE (CWE-862): Missing Authorization check\n    // Allows any authenticated user (e.g. Alice or Bob) to invoke administrative functions\n    next();\n  }\n",
                        "after": "  if (req.session.user.role !== 'admin') {\n    return res.status(403).json({\n      error: 'Forbidden',\n      message: 'Administrator privilege required.'\n    });\n  }\n  next();\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-1004",
        "cweId": "CWE-1004",
        "endpoint": "/api/auth/login",
        "explanation": "The authentication and session cookies can omit HttpOnly. Set HttpOnly in the cookie issuer, session defaults, and per-request overrides so the demo switch cannot remove the flag. Normal HTTPS login and session reuse must still work.",
        "files": [
            {
                "path": "src/middleware/auth.ts",
                "sha256": "34b29b0f350fed8f2d1c572fbc0eeb5b42b71e78ef77f76e2451f7aa2fbbe6f3",
                "edits": [
                    {
                        "before": "      httpOnly: false,\n      secure: false,\n      sameSite: 'lax',\n      path: '/'\n    });\n\n    if (req.session) {\n      req.session.cookie.httpOnly = false;\n",
                        "after": "      httpOnly: true,\n      secure: false,\n      sameSite: 'lax',\n      path: '/'\n    });\n\n    if (req.session) {\n      req.session.cookie.httpOnly = true;\n"
                    }
                ]
            },
            {
                "path": "src/app.ts",
                "sha256": "1f212abe9531c6c48eb605d61d967981d18bc7ba65c0f4279bc3506056dd15c1",
                "edits": [
                    {
                        "before": "      httpOnly: false,\n      secure: false,\n      sameSite: 'lax',\n      maxAge: 24 * 60 * 60 * 1000\n    }\n  });\n\n  app.use(sessionMiddleware);\n\n  // Dynamic session cookie attributes per security mode\n  app.use((req, res, next) => {\n    const fixed = isFixedMode(req);\n    if (req.session && req.session.cookie) {\n      req.session.cookie.httpOnly = fixed;\n",
                        "after": "      httpOnly: true,\n      secure: false,\n      sameSite: 'lax',\n      maxAge: 24 * 60 * 60 * 1000\n    }\n  });\n\n  app.use(sessionMiddleware);\n\n  // Dynamic session cookie attributes per security mode\n  app.use((req, res, next) => {\n    const fixed = isFixedMode(req);\n    if (req.session && req.session.cookie) {\n      req.session.cookie.httpOnly = true;\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-614",
        "cweId": "CWE-614",
        "endpoint": "/api/auth/login",
        "explanation": "The authentication and session cookies can omit Secure. Set Secure in the issuer, session defaults, and all overrides. Deploy through HTTPS; an HTTP-only client cannot reuse these cookies. Configure a trusted TLS proxy explicitly when one terminates HTTPS.",
        "files": [
            {
                "path": "src/middleware/auth.ts",
                "sha256": "34b29b0f350fed8f2d1c572fbc0eeb5b42b71e78ef77f76e2451f7aa2fbbe6f3",
                "edits": [
                    {
                        "before": "      if (req.secure || process.env.COOKIE_SECURE === 'true') {\n        req.session.cookie.secure = true;\n      }\n    }\n  } else {\n    // VULNERABLE:\n    // CWE-1004: httpOnly = false (accessible via document.cookie in browser JavaScript)\n    // CWE-614: secure = false (transmitted in cleartext over unencrypted HTTP)\n    res.cookie('auth_token', userSessionToken, {\n      httpOnly: false,\n      secure: false,\n      sameSite: 'lax',\n      path: '/'\n    });\n\n    if (req.session) {\n      req.session.cookie.httpOnly = false;\n      req.session.cookie.secure = false;\n",
                        "after": "      req.session.cookie.secure = true;\n    }\n  } else {\n    // VULNERABLE:\n    // CWE-1004: httpOnly = false (accessible via document.cookie in browser JavaScript)\n    // CWE-614: secure = false (transmitted in cleartext over unencrypted HTTP)\n    res.cookie('auth_token', userSessionToken, {\n      httpOnly: false,\n      secure: true,\n      sameSite: 'lax',\n      path: '/'\n    });\n\n    if (req.session) {\n      req.session.cookie.httpOnly = false;\n      req.session.cookie.secure = true;\n"
                    }
                ]
            },
            {
                "path": "src/app.ts",
                "sha256": "1f212abe9531c6c48eb605d61d967981d18bc7ba65c0f4279bc3506056dd15c1",
                "edits": [
                    {
                        "before": "      secure: false,\n      sameSite: 'lax',\n      maxAge: 24 * 60 * 60 * 1000\n    }\n  });\n\n  app.use(sessionMiddleware);\n\n  // Dynamic session cookie attributes per security mode\n  app.use((req, res, next) => {\n    const fixed = isFixedMode(req);\n    if (req.session && req.session.cookie) {\n      req.session.cookie.httpOnly = fixed;\n      req.session.cookie.secure = fixed && (req.secure || process.env.COOKIE_SECURE === 'true');\n",
                        "after": "      secure: true,\n      sameSite: 'lax',\n      maxAge: 24 * 60 * 60 * 1000\n    }\n  });\n\n  app.use(sessionMiddleware);\n\n  // Dynamic session cookie attributes per security mode\n  app.use((req, res, next) => {\n    const fixed = isFixedMode(req);\n    if (req.session && req.session.cookie) {\n      req.session.cookie.httpOnly = fixed;\n      req.session.cookie.secure = true;\n"
                    }
                ]
            }
        ]
    },
    {
        "id": "express-storefront-cwe-942",
        "cweId": "CWE-942",
        "endpoint": "/api/products",
        "explanation": "The CORS middleware reflects untrusted origins with credentials. Match complete origins against the existing trusted-origin list and vary cached responses by Origin. Omit CORS grants for all other origins, including null. Review the allowlist before deployment; this does not by itself establish prior data disclosure.",
        "files": [
            {
                "path": "src/middleware/cors.ts",
                "sha256": "a271e4c6e899fdafb9b02d95b52ade8a9030300dcc74da8a42e3899200df7be5",
                "edits": [
                    {
                        "before": "  const fixed = isFixedMode(req);\n\n  if (fixed) {\n    // FIXED: Only whitelist approved origins, do not reflect arbitrary origins with credentials\n    if (origin && TRUSTED_ORIGINS.includes(origin)) {\n      res.setHeader('Access-Control-Allow-Origin', origin);\n      res.setHeader('Access-Control-Allow-Credentials', 'true');\n    } else {\n      // Disallow or allow null without credentials\n      res.setHeader('Access-Control-Allow-Origin', 'null');\n    }\n  } else {\n    // VULNERABLE (CWE-942): Dynamically reflect any untrusted Origin header with credentials\n    if (origin) {\n      res.setHeader('Access-Control-Allow-Origin', origin);\n      res.setHeader('Access-Control-Allow-Credentials', 'true');\n    } else {\n      res.setHeader('Access-Control-Allow-Origin', '*');\n    }\n",
                        "after": "  // Match complete trusted origins. Never grant credentials to an untrusted or null origin.\n  res.vary('Origin');\n  if (origin && TRUSTED_ORIGINS.includes(origin)) {\n    res.setHeader('Access-Control-Allow-Origin', origin);\n    res.setHeader('Access-Control-Allow-Credentials', 'true');\n"
                    }
                ]
            }
        ]
    }
]);
