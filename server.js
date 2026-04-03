require("dotenv").config();

// Core dependencies for the API, authentication, and MongoDB access.
const bcrypt = require("bcryptjs");
const express = require("express");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const AppleStrategy = require("passport-apple");
const path = require("path");

// Express app setup.
const app = express();
app.set("query parser", "extended");

// Environment-driven configuration.
const PORT = Number(process.env.PORT) || 5000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "inventory-system";
const COLLECTION_NAME = "items";
const ADMINS_COLLECTION_NAME = "admins";
const WORKERS_COLLECTION_NAME = "workers";
const USERS_COLLECTION_NAME = "users";
const ORDERS_COLLECTION_NAME = "orders";
const RESOURCE_PATHS = ["/products", "/api/items"];
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const MAX_BULK_OPERATIONS = 100;
const MAX_IMAGE_BYTES = Number(process.env.MAX_IMAGE_BYTES) || 2 * 1024 * 1024;
const ALLOWED_IMAGE_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);
const JWT_SECRET = process.env.JWT_SECRET || "dev-insecure-change-me";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const OAUTH_REDIRECT_BASE =
  process.env.OAUTH_REDIRECT_BASE || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL || `${OAUTH_REDIRECT_BASE}/auth/oauth/google/callback`;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_CALLBACK_URL =
  process.env.GITHUB_CALLBACK_URL || `${OAUTH_REDIRECT_BASE}/auth/oauth/github/callback`;
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID;
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID;
const APPLE_KEY_ID = process.env.APPLE_KEY_ID;
const APPLE_PRIVATE_KEY = process.env.APPLE_PRIVATE_KEY;
const APPLE_CALLBACK_URL =
  process.env.APPLE_CALLBACK_URL || `${OAUTH_REDIRECT_BASE}/auth/oauth/apple/callback`;

// Shared runtime state populated after the database connection succeeds.
let client;
let collection;
let adminsCollection;
let workersCollection;
let usersCollection;
let ordersCollection;
let server;

// Global middleware for security headers, JSON parsing, CORS, and static files.
app.disable("x-powered-by");
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(passport.initialize());
const PUBLIC_DIR = path.join(__dirname, "public");
app.use(
  express.static(PUBLIC_DIR, {
    etag: true,
    maxAge: "7d",
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-cache");
      }
    },
  })
);
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Database helpers keep route handlers small and fail fast if MongoDB is unavailable.
function getCollection() {
  if (!collection) {
    const error = new Error("Database is not connected");
    error.statusCode = 503;
    throw error;
  }

  return collection;
}

function getAdminsCollection() {
  if (!adminsCollection) {
    const error = new Error("Admin database is not connected");
    error.statusCode = 503;
    throw error;
  }

  return adminsCollection;
}

function getWorkersCollection() {
  if (!workersCollection) {
    const error = new Error("Worker database is not connected");
    error.statusCode = 503;
    throw error;
  }

  return workersCollection;
}

function getUsersCollection() {
  if (!usersCollection) {
    const error = new Error("User database is not connected");
    error.statusCode = 503;
    throw error;
  }

  return usersCollection;
}

function getOrdersCollection() {
  if (!ordersCollection) {
    const error = new Error("Orders database is not connected");
    error.statusCode = 503;
    throw error;
  }

  return ordersCollection;
}

// Normalizes item data so every stored document has creation and update timestamps.
function buildItemDocument(payload) {
  const now = new Date();

  return {
    ...payload,
    createdAt: now,
    updatedAt: now,
  };
}

// Data access helpers for inventory records.
async function listItems(filter = {}, options = {}) {
  const { sort = { createdAt: -1, _id: -1 }, page = 1, limit = 20, cursor } = options;
  const query = { ...filter };

  if (cursor) {
    query._id = { ...(query._id || {}), $lt: parseObjectId(cursor) };
  }

  const mongoCursor = getCollection().find(query).sort(sort).limit(limit);

  if (!cursor) {
    mongoCursor.skip((page - 1) * limit);
  }

  return mongoCursor.toArray();
}

async function countItems(filter = {}) {
  return getCollection().countDocuments(filter);
}

async function findItemById(id) {
  return getCollection().findOne({ _id: parseObjectId(id) });
}

async function createItem(payload) {
  const result = await getCollection().insertOne(buildItemDocument(payload));
  return getCollection().findOne({ _id: result.insertedId });
}

async function updateItem(id, payload) {
  return getCollection().findOneAndUpdate(
    { _id: parseObjectId(id) },
    {
      $set: {
        ...payload,
        updatedAt: new Date(),
      },
    },
    { returnDocument: "after" }
  );
}

async function patchItem(id, payload) {
  return getCollection().findOneAndUpdate(
    { _id: parseObjectId(id) },
    {
      $set: {
        ...payload,
        updatedAt: new Date(),
      },
    },
    { returnDocument: "after" }
  );
}

async function deleteItem(id) {
  return getCollection().findOneAndDelete({ _id: parseObjectId(id) });
}

function resolveImageBuffer(value) {
  if (!value) {
    return null;
  }

  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (value.buffer && Buffer.isBuffer(value.buffer)) {
    return value.buffer;
  }

  if (value.data && Buffer.isBuffer(value.data)) {
    return value.data;
  }

  if (value.data && value.data.buffer && Buffer.isBuffer(value.data.buffer)) {
    return value.data.buffer;
  }

  if (Array.isArray(value.data)) {
    return Buffer.from(value.data);
  }

  return null;
}

function serializeItem(item) {
  if (!item || typeof item !== "object") {
    return item;
  }

  if (typeof item.image === "string") {
    return item;
  }

  const output = { ...item };

  if (output.image && typeof output.image === "object") {
    const buffer = resolveImageBuffer(output.image.data || output.image);
    const mimeType = output.image.mimeType;

    if (buffer && mimeType) {
      output.image = `data:${mimeType};base64,${buffer.toString("base64")}`;
    } else {
      output.image = null;
    }
  }

  return output;
}

// Converts the dashboard/API bulk format into MongoDB bulkWrite operations.
async function runBulkOperations(operations, ordered = false) {
  const bulkOperations = operations.map((operation) => {
    if (!operation || typeof operation !== "object" || Array.isArray(operation)) {
      const error = new Error("Each bulk operation must be an object");
      error.statusCode = 400;
      throw error;
    }

    if (!operation.type) {
      return {
        insertOne: {
          document: buildItemDocument(validateItemPayload(operation)),
        },
      };
    }

    if (operation.type === "insert") {
      return {
        insertOne: {
          document: buildItemDocument(validateItemPayload(operation.data)),
        },
      };
    }

    if (operation.type === "update") {
      return {
        updateOne: {
          filter: { _id: parseObjectId(operation.id) },
          update: {
            $set: {
              ...validatePartialItemPayload(operation.data),
              updatedAt: new Date(),
            },
          },
        },
      };
    }

    if (operation.type === "delete") {
      return {
        deleteOne: {
          filter: { _id: parseObjectId(operation.id) },
        },
      };
    }

    const error = new Error('Bulk operation type must be "insert", "update", or "delete"');
    error.statusCode = 400;
    throw error;
  });

  return getCollection().bulkWrite(bulkOperations, { ordered });
}

// Admin data helpers.
async function countAdmins() {
  return getAdminsCollection().countDocuments();
}

async function findAdminByUsername(username) {
  return getAdminsCollection().findOne({ username });
}

async function findAdminById(id) {
  return getAdminsCollection().findOne({ _id: parseObjectId(id) });
}

function sanitizeAdmin(admin) {
  return {
    id: String(admin._id),
    username: admin.username,
    createdAt: admin.createdAt,
  };
}

// Worker data helpers.
async function countWorkers() {
  return getWorkersCollection().countDocuments();
}

async function findWorkerByUsername(username) {
  return getWorkersCollection().findOne({ username });
}

async function findWorkerById(id) {
  return getWorkersCollection().findOne({ _id: parseObjectId(id) });
}

function sanitizeWorker(worker) {
  return {
    id: String(worker._id),
    username: worker.username,
    role: "worker",
    createdAt: worker.createdAt,
  };
}

// User data helpers.
async function countUsers() {
  return getUsersCollection().countDocuments();
}

async function findUserByUsername(username) {
  return getUsersCollection().findOne({ username });
}

async function findUserById(id) {
  return getUsersCollection().findOne({ _id: parseObjectId(id) });
}

function sanitizeUser(user) {
  return {
    id: String(user._id),
    username: user.username,
    role: "user",
    createdAt: user.createdAt,
  };
}

async function listAdmins() {
  const admins = await getAdminsCollection()
    .find({})
    .sort({ createdAt: -1, _id: -1 })
    .toArray();
  return admins.map(sanitizeAdmin);
}

async function listWorkers() {
  const workers = await getWorkersCollection()
    .find({})
    .sort({ createdAt: -1, _id: -1 })
    .toArray();
  return workers.map(sanitizeWorker);
}

async function listUsers() {
  const users = await getUsersCollection()
    .find({})
    .sort({ createdAt: -1, _id: -1 })
    .toArray();
  return users.map(sanitizeUser);
}

async function findUserByProvider(provider, providerId) {
  return getUsersCollection().findOne({ provider, providerId });
}

async function findUserByEmail(email) {
  if (!email) {
    return null;
  }

  return getUsersCollection().findOne({ email });
}

function normalizeUsername(value) {
  const base = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "");
  if (base.length >= 3) {
    return base.slice(0, 20);
  }
  return `user${Math.floor(Math.random() * 10000)}`;
}

async function generateUniqueUsername(seed) {
  const base = normalizeUsername(seed);
  let candidate = base;
  let suffix = 0;

  while (await findUserByUsername(candidate)) {
    suffix += 1;
    candidate = `${base}${suffix}`;
  }

  return candidate;
}

async function upsertOAuthUser({ provider, providerId, email, displayName }) {
  const existingProvider = await findUserByProvider(provider, providerId);
  if (existingProvider) {
    return existingProvider;
  }

  if (email) {
    const existingEmail = await findUserByEmail(email);
    if (existingEmail) {
      await getUsersCollection().updateOne(
        { _id: existingEmail._id },
        {
          $set: {
            provider,
            providerId,
            email,
            updatedAt: new Date(),
          },
        }
      );
      return getUsersCollection().findOne({ _id: existingEmail._id });
    }
  }

  const usernameSeed = email ? email.split("@")[0] : displayName || `${provider}${providerId}`;
  const username = await generateUniqueUsername(usernameSeed);

  const user = {
    username,
    passwordHash: null,
    provider,
    providerId,
    email: email || null,
    createdAt: new Date(),
  };

  const result = await getUsersCollection().insertOne(user);
  return getUsersCollection().findOne({ _id: result.insertedId });
}

// Tokens can be configured to expire or remain active depending on JWT_EXPIRES_IN.
function getJwtSignOptions() {
  const rawValue = String(JWT_EXPIRES_IN || "").trim().toLowerCase();

  if (!rawValue || ["never", "none", "false", "0", "off"].includes(rawValue)) {
    return {};
  }

  return { expiresIn: JWT_EXPIRES_IN };
}

function signAccountToken({ id, username, role }) {
  return jwt.sign(
    {
      sub: String(id),
      username,
      role,
    },
    JWT_SECRET,
    getJwtSignOptions()
  );
}

function signAdminToken(admin) {
  return signAccountToken({ id: admin._id, username: admin.username, role: "admin" });
}

function signWorkerToken(worker) {
  return signAccountToken({ id: worker._id, username: worker.username, role: "worker" });
}

function signUserToken(user) {
  return signAccountToken({ id: user._id, username: user.username, role: "user" });
}

function normalizePrivateKey(rawValue) {
  if (!rawValue) {
    return "";
  }

  if (rawValue.includes("-----BEGIN")) {
    return rawValue.replace(/\\n/g, "\n");
  }

  try {
    const decoded = Buffer.from(rawValue, "base64").toString("utf8");
    if (decoded.includes("-----BEGIN")) {
      return decoded;
    }
  } catch (_error) {
    // Ignore base64 failures.
  }

  return rawValue.replace(/\\n/g, "\n");
}

const oauthProviders = {
  google: {
    strategy: "google",
    configured: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    scope: ["profile", "email"],
  },
  github: {
    strategy: "github",
    configured: Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET),
    scope: ["user:email"],
  },
  apple: {
    strategy: "apple",
    configured: Boolean(APPLE_CLIENT_ID && APPLE_TEAM_ID && APPLE_KEY_ID && APPLE_PRIVATE_KEY),
    scope: ["name", "email"],
  },
};

configureOAuthStrategies();

function configureOAuthStrategies() {
  if (oauthProviders.google.configured) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: GOOGLE_CLIENT_ID,
          clientSecret: GOOGLE_CLIENT_SECRET,
          callbackURL: GOOGLE_CALLBACK_URL,
        },
        (_accessToken, _refreshToken, profile, done) => {
          const email = profile.emails?.[0]?.value || null;
          const displayName = profile.displayName || profile.username || email || "google-user";
          done(null, {
            provider: "google",
            providerId: profile.id,
            email,
            displayName,
          });
        }
      )
    );
  }

  if (oauthProviders.github.configured) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: GITHUB_CLIENT_ID,
          clientSecret: GITHUB_CLIENT_SECRET,
          callbackURL: GITHUB_CALLBACK_URL,
          scope: ["user:email"],
        },
        (_accessToken, _refreshToken, profile, done) => {
          const email = profile.emails?.[0]?.value || null;
          const displayName = profile.username || profile.displayName || email || "github-user";
          done(null, {
            provider: "github",
            providerId: String(profile.id),
            email,
            displayName,
          });
        }
      )
    );
  }

  if (oauthProviders.apple.configured) {
    passport.use(
      new AppleStrategy(
        {
          clientID: APPLE_CLIENT_ID,
          teamID: APPLE_TEAM_ID,
          keyID: APPLE_KEY_ID,
          callbackURL: APPLE_CALLBACK_URL,
          privateKey: normalizePrivateKey(APPLE_PRIVATE_KEY),
          scope: ["name", "email"],
        },
        (_accessToken, _refreshToken, idToken, profile, done) => {
          const email = profile?.email || null;
          const displayName =
            profile?.name?.firstName || profile?.name?.lastName
              ? `${profile.name.firstName || ""} ${profile.name.lastName || ""}`.trim()
              : email || "apple-user";
          done(null, {
            provider: "apple",
            providerId: profile?.id || idToken?.sub || "apple-user",
            email,
            displayName,
          });
        }
      )
    );
  }
}

function getOAuthProviderConfig(provider) {
  return oauthProviders[provider] || null;
}

function buildOAuthErrorRedirect(message) {
  return `/user-login.html#error=${encodeURIComponent(message)}`;
}

async function handleOAuthCallback(req, res, next, provider) {
  const config = getOAuthProviderConfig(provider);
  if (!config || !config.configured) {
    return res.redirect(buildOAuthErrorRedirect("OAuth provider is not configured."));
  }

  return passport.authenticate(config.strategy, { session: false }, async (error, profile) => {
    if (error || !profile) {
      return res.redirect(buildOAuthErrorRedirect("OAuth login failed. Please try again."));
    }

    try {
      const user = await upsertOAuthUser(profile);
      const token = signUserToken(user);
      return res.redirect(`/user-login.html#token=${encodeURIComponent(token)}`);
    } catch (err) {
      return next(err);
    }
  })(req, res, next);
}

// Protects write routes and admin-only profile routes with a Bearer token.
async function requireAdmin(req, _res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      const error = new Error("Authorization token is required");
      error.statusCode = 401;
      throw error;
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") {
      const error = new Error("Admin access required");
      error.statusCode = 403;
      throw error;
    }
    const admin = await getAdminsCollection().findOne({ _id: parseObjectId(payload.sub) });

    if (!admin) {
      const error = new Error("Admin account not found");
      error.statusCode = 401;
      throw error;
    }

    req.admin = sanitizeAdmin(admin);
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      error.statusCode = 401;
      error.message = "Invalid or expired token";
    }

    next(error);
  }
}

// Protects inventory write routes for admin + worker accounts.
async function requireStaff(req, _res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      const error = new Error("Authorization token is required");
      error.statusCode = 401;
      throw error;
    }

    const payload = jwt.verify(token, JWT_SECRET);

    if (!payload.role || !["admin", "worker"].includes(payload.role)) {
      const error = new Error("Staff access required");
      error.statusCode = 403;
      throw error;
    }

    const account =
      payload.role === "admin"
        ? await getAdminsCollection().findOne({ _id: parseObjectId(payload.sub) })
        : await getWorkersCollection().findOne({ _id: parseObjectId(payload.sub) });

    if (!account) {
      const error = new Error("Account not found");
      error.statusCode = 401;
      throw error;
    }

    req.staff = payload.role === "admin" ? sanitizeAdmin(account) : sanitizeWorker(account);
    req.staff.role = payload.role;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      error.statusCode = 401;
      error.message = "Invalid or expired token";
    }

    next(error);
  }
}

// Protects user-only routes.
async function requireUser(req, _res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      const error = new Error("Authorization token is required");
      error.statusCode = 401;
      throw error;
    }

    const payload = jwt.verify(token, JWT_SECRET);

    if (payload.role !== "user") {
      const error = new Error("User access required");
      error.statusCode = 403;
      throw error;
    }

    const user = await getUsersCollection().findOne({ _id: parseObjectId(payload.sub) });

    if (!user) {
      const error = new Error("User account not found");
      error.statusCode = 401;
      throw error;
    }

    req.user = sanitizeUser(user);
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      error.statusCode = 401;
      error.message = "Invalid or expired token";
    }

    next(error);
  }
}

// Protects worker-only routes.
async function requireWorker(req, _res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      const error = new Error("Authorization token is required");
      error.statusCode = 401;
      throw error;
    }

    const payload = jwt.verify(token, JWT_SECRET);

    if (payload.role !== "worker") {
      const error = new Error("Worker access required");
      error.statusCode = 403;
      throw error;
    }

    const worker = await getWorkersCollection().findOne({ _id: parseObjectId(payload.sub) });

    if (!worker) {
      const error = new Error("Worker account not found");
      error.statusCode = 401;
      throw error;
    }

    req.worker = sanitizeWorker(worker);
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      error.statusCode = 401;
      error.message = "Invalid or expired token";
    }

    next(error);
  }
}

// Public status routes.
app.get("/", (_req, res) => {
  res.json({
    status: "ok",
    message: "Inventory system server is running",
    endpoints: [
      "GET /health",
      "POST /auth/register",
      "GET /auth/login",
      "POST /auth/login",
      "POST /auth/worker/register",
      "POST /auth/worker/login",
      "GET /auth/worker/me",
      "POST /auth/user/register",
      "POST /auth/user/login",
      "GET /auth/user/me",
      "GET /auth/oauth/google",
      "GET /auth/oauth/github",
      "GET /auth/oauth/apple",
      "GET /admin/admins",
      "GET /admin/workers",
      "GET /admin/users",
      "DELETE /admin/admins/:id",
      "DELETE /admin/workers/:id",
      "DELETE /admin/users/:id",
      "GET /admin/orders",
      "POST /admin/orders/:id/approve",
      "POST /admin/orders/:id/refund",
      "POST /admin/orders/:id/reopen",
      "GET /products",
      "GET /products?price[$gte]=10&price[$lte]=100",
      "GET /products?name[$regex]=lap",
      "GET /products?sortBy=price&order=asc&page=1&limit=10",
      "GET /products?limit=10&cursor=<last_id>",
      "GET /products/stats/count",
      "GET /products/stats/average-price",
      "GET /products/stats/top-expensive?limit=3",
      "POST /products",
      "POST /products/bulk",
      "GET /products/:id",
      "PUT /products/:id",
      "PATCH /products/:id",
      "DELETE /products/:id",
      "GET /api/items",
      "POST /api/items",
      "POST /api/items/bulk",
      "GET /api/items/:id",
      "PUT /api/items/:id",
      "PATCH /api/items/:id",
      "DELETE /api/items/:id",
      "GET /orders",
      "POST /orders",
    ],
  });
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    databaseConnected: Boolean(collection),
    databaseName: DB_NAME,
    collectionName: COLLECTION_NAME,
    atlasConfigured: typeof MONGO_URI === "string" && MONGO_URI.includes("mongodb+srv://"),
    authConfigured: Boolean(JWT_SECRET && JWT_SECRET !== "dev-insecure-change-me"),
  });
});

// Authentication routes.
app.post("/auth/register", async (req, res, next) => {
  try {
    const existingAdmins = await countAdmins();

    if (existingAdmins > 0) {
      await new Promise((resolve, reject) => {
        requireAdmin(req, res, (error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }

    const { username, password } = validateAdminCredentials(req.body);
    const existingAdmin = await findAdminByUsername(username);

    if (existingAdmin) {
      const error = new Error("Admin username already exists");
      error.statusCode = 409;
      throw error;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const admin = {
      username,
      passwordHash,
      createdAt: new Date(),
    };

    const result = await getAdminsCollection().insertOne(admin);
    const createdAdmin = await getAdminsCollection().findOne({ _id: result.insertedId });
    const token = signAdminToken(createdAdmin);

    res.status(201).json({
      admin: sanitizeAdmin(createdAdmin),
      token,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/auth/login", (_req, res) => {
  res.json({
    message: "Send a POST request to /auth/login with username and password to receive a JWT token.",
    requiredBody: {
      username: "admin",
      password: "your-password",
    },
  });
});

app.get("/auth/status", async (_req, res, next) => {
  try {
    const adminCount = await countAdmins();

    res.json({
      hasAdmins: adminCount > 0,
      adminCount,
      loginPath: "/auth/login",
      registerPath: "/auth/register",
    });
  } catch (error) {
    next(error);
  }
});

app.get("/auth/worker/status", async (_req, res, next) => {
  try {
    const workerCount = await countWorkers();

    res.json({
      hasWorkers: workerCount > 0,
      workerCount,
      loginPath: "/auth/worker/login",
      registerPath: "/auth/worker/register",
    });
  } catch (error) {
    next(error);
  }
});

app.get("/auth/user/status", async (_req, res, next) => {
  try {
    const userCount = await countUsers();

    res.json({
      hasUsers: userCount > 0,
      userCount,
      loginPath: "/auth/user/login",
      registerPath: "/auth/user/register",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const { username, password } = validateAdminCredentials(req.body);
    const admin = await findAdminByUsername(username);

    if (!admin) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    const passwordMatches = await bcrypt.compare(password, admin.passwordHash);

    if (!passwordMatches) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    res.json({
      admin: sanitizeAdmin(admin),
      token: signAdminToken(admin),
    });
  } catch (error) {
    next(error);
  }
});

// Worker auth routes (created by admins).
app.post("/auth/worker/register", requireAdmin, async (req, res, next) => {
  try {
    const { username, password } = validateAdminCredentials(req.body);
    const existingWorker = await findWorkerByUsername(username);

    if (existingWorker) {
      const error = new Error("Worker username already exists");
      error.statusCode = 409;
      throw error;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const worker = {
      username,
      passwordHash,
      createdAt: new Date(),
    };

    const result = await getWorkersCollection().insertOne(worker);
    const createdWorker = await getWorkersCollection().findOne({ _id: result.insertedId });

    res.status(201).json({
      worker: sanitizeWorker(createdWorker),
      token: signWorkerToken(createdWorker),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/worker/login", async (req, res, next) => {
  try {
    const { username, password } = validateAdminCredentials(req.body);
    const worker = await findWorkerByUsername(username);

    if (!worker) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    const passwordMatches = await bcrypt.compare(password, worker.passwordHash);

    if (!passwordMatches) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    res.json({
      worker: sanitizeWorker(worker),
      token: signWorkerToken(worker),
    });
  } catch (error) {
    next(error);
  }
});

app.get("/auth/worker/me", requireWorker, async (req, res) => {
  res.json({
    worker: req.worker,
  });
});

// User auth routes (self-service).
app.post("/auth/user/register", async (req, res, next) => {
  try {
    const { username, password } = validateAdminCredentials(req.body);
    const existingUser = await findUserByUsername(username);

    if (existingUser) {
      const error = new Error("Username already exists");
      error.statusCode = 409;
      throw error;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      username,
      passwordHash,
      createdAt: new Date(),
    };

    const result = await getUsersCollection().insertOne(user);
    const createdUser = await getUsersCollection().findOne({ _id: result.insertedId });

    res.status(201).json({
      user: sanitizeUser(createdUser),
      token: signUserToken(createdUser),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/user/login", async (req, res, next) => {
  try {
    const { username, password } = validateAdminCredentials(req.body);
    const user = await findUserByUsername(username);

    if (!user) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    if (!user.passwordHash) {
      const error = new Error("This account uses social login. Please sign in with your provider.");
      error.statusCode = 401;
      throw error;
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
      const error = new Error("Invalid username or password");
      error.statusCode = 401;
      throw error;
    }

    res.json({
      user: sanitizeUser(user),
      token: signUserToken(user),
    });
  } catch (error) {
    next(error);
  }
});

app.get("/auth/user/me", requireUser, async (req, res) => {
  res.json({
    user: req.user,
  });
});

// Admin management routes (admins, workers, users).
app.get("/admin/admins", requireAdmin, async (_req, res, next) => {
  try {
    const admins = await listAdmins();
    res.json({ data: admins });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/workers", requireAdmin, async (_req, res, next) => {
  try {
    const workers = await listWorkers();
    res.json({ data: workers });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/users", requireAdmin, async (_req, res, next) => {
  try {
    const users = await listUsers();
    res.json({ data: users });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/orders", requireAdmin, async (_req, res, next) => {
  try {
    const orders = await getOrdersCollection()
      .find({})
      .sort({ createdAt: -1, _id: -1 })
      .toArray();

    res.json({ data: orders });
  } catch (error) {
    next(error);
  }
});

app.post("/admin/orders/:id/approve", requireAdmin, async (req, res, next) => {
  try {
    const orderId = parseObjectId(req.params.id);
    const now = new Date();

    const result = await getOrdersCollection().findOneAndUpdate(
      { _id: orderId, status: "placed" },
      {
        $set: {
          status: "approved",
          approvedAt: now,
          approvedBy: req.admin.username,
        },
      },
      { returnDocument: "after" }
    );

    const order = result?.value;

    if (!order) {
      const error = new Error("Order not found or already processed");
      error.statusCode = 404;
      throw error;
    }

    res.json({ message: "Order approved", order });
  } catch (error) {
    next(error);
  }
});

app.post("/admin/orders/:id/refund", requireAdmin, async (req, res, next) => {
  try {
    const orderId = parseObjectId(req.params.id);
    const now = new Date();

    const result = await getOrdersCollection().findOneAndUpdate(
      { _id: orderId, status: "cancelled" },
      {
        $set: {
          status: "refunded",
          refundedAt: now,
          refundedBy: req.admin.username,
        },
      },
      { returnDocument: "after" }
    );

    const order = result?.value;

    if (!order) {
      const error = new Error("Order not found or not cancelled");
      error.statusCode = 404;
      throw error;
    }

    res.json({ message: "Order refunded", order });
  } catch (error) {
    next(error);
  }
});

app.post("/admin/orders/:id/reopen", requireAdmin, async (req, res, next) => {
  try {
    const orderId = parseObjectId(req.params.id);
    const order = await getOrdersCollection().findOne({ _id: orderId });

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (order.status !== "cancelled") {
      const error = new Error("Only cancelled orders can be reopened");
      error.statusCode = 400;
      throw error;
    }

    const items = Array.isArray(order.items) ? order.items : [];
    if (items.length === 0) {
      const error = new Error("Order has no items to reopen");
      error.statusCode = 400;
      throw error;
    }

    const productIds = items.map((item) => parseObjectId(item.productId));
    const products = await getCollection()
      .find({ _id: { $in: productIds } })
      .toArray();
    const productMap = new Map(products.map((product) => [String(product._id), product]));

    for (const item of items) {
      const product = productMap.get(String(item.productId));
      if (!product) {
        const error = new Error(`Product missing for order item ${item.productId}`);
        error.statusCode = 404;
        throw error;
      }
      if (product.quantity < item.quantity) {
        const error = new Error(`Insufficient stock to reopen ${product.name}`);
        error.statusCode = 400;
        throw error;
      }
    }

    const now = new Date();
    const stockOps = items.map((item) => ({
      updateOne: {
        filter: { _id: parseObjectId(item.productId) },
        update: {
          $inc: { quantity: -item.quantity },
          $set: { updatedAt: now },
        },
      },
    }));

    await getCollection().bulkWrite(stockOps, { ordered: true });

    const result = await getOrdersCollection().findOneAndUpdate(
      { _id: orderId },
      {
        $set: {
          status: "placed",
          reopenedAt: now,
          reopenedBy: req.admin.username,
          cancelledAt: null,
          cancelledBy: null,
        },
      },
      { returnDocument: "after" }
    );

    res.json({ message: "Order reopened", order: result?.value });
  } catch (error) {
    next(error);
  }
});

app.delete("/admin/admins/:id", requireAdmin, async (req, res, next) => {
  try {
    if (req.admin.id === req.params.id) {
      const error = new Error("You cannot delete your own admin account");
      error.statusCode = 400;
      throw error;
    }

    const result = await getAdminsCollection().findOneAndDelete({
      _id: parseObjectId(req.params.id),
    });
    const admin = result?.value;

    if (!admin) {
      return res.status(404).json({ error: "Admin account not found" });
    }

    res.json({
      message: "Admin deleted successfully",
      admin: sanitizeAdmin(admin),
    });
  } catch (error) {
    next(error);
  }
});

app.delete("/admin/workers/:id", requireAdmin, async (req, res, next) => {
  try {
    const result = await getWorkersCollection().findOneAndDelete({
      _id: parseObjectId(req.params.id),
    });
    const worker = result?.value;

    if (!worker) {
      return res.status(404).json({ error: "Worker account not found" });
    }

    res.json({
      message: "Worker deleted successfully",
      worker: sanitizeWorker(worker),
    });
  } catch (error) {
    next(error);
  }
});

app.delete("/admin/users/:id", requireAdmin, async (req, res, next) => {
  try {
    const result = await getUsersCollection().findOneAndDelete({
      _id: parseObjectId(req.params.id),
    });
    const user = result?.value;

    if (!user) {
      return res.status(404).json({ error: "User account not found" });
    }

    res.json({
      message: "User deleted successfully",
      user: sanitizeUser(user),
    });
  } catch (error) {
    next(error);
  }
});

// OAuth routes for user signup/login.
app.get("/auth/oauth/:provider", (req, res, next) => {
  const provider = req.params.provider;
  const config = getOAuthProviderConfig(provider);

  if (!config || !config.configured) {
    return res.redirect(buildOAuthErrorRedirect("OAuth provider is not configured."));
  }

  return passport.authenticate(config.strategy, {
    session: false,
    scope: config.scope,
  })(req, res, next);
});

app.get("/auth/oauth/:provider/callback", (req, res, next) => {
  return handleOAuthCallback(req, res, next, req.params.provider);
});

app.post("/auth/oauth/apple/callback", (req, res, next) => {
  return handleOAuthCallback(req, res, next, "apple");
});

app.get("/auth/me", requireAdmin, async (req, res) => {
  res.json({
    admin: req.admin,
  });
});

app.patch("/auth/me", requireAdmin, async (req, res, next) => {
  try {
    const { username, currentPassword, newPassword } = validateAdminUpdatePayload(req.body);
    const admin = await findAdminById(req.admin.id);

    if (!admin) {
      const error = new Error("Admin account not found");
      error.statusCode = 404;
      throw error;
    }

    const passwordMatches = await bcrypt.compare(currentPassword, admin.passwordHash);

    if (!passwordMatches) {
      const error = new Error("Current password is incorrect");
      error.statusCode = 401;
      throw error;
    }

    const update = {
      updatedAt: new Date(),
    };

    if (username && username !== admin.username) {
      const existingAdmin = await findAdminByUsername(username);

      if (existingAdmin && String(existingAdmin._id) !== String(admin._id)) {
        const error = new Error("Admin username already exists");
        error.statusCode = 409;
        throw error;
      }

      update.username = username;
    }

    if (newPassword) {
      update.passwordHash = await bcrypt.hash(newPassword, 10);
    }

    const result = await getAdminsCollection().findOneAndUpdate(
      { _id: admin._id },
      { $set: update },
      { returnDocument: "after" }
    );

    const updatedAdmin = result;

    res.json({
      admin: sanitizeAdmin(updatedAdmin),
      token: signAdminToken(updatedAdmin),
    });
  } catch (error) {
    next(error);
  }
});

// Aggregation/statistics routes used by the dashboard.
app.get("/products/stats/count", async (_req, res, next) => {
  try {
    const totalProducts = await countItems();

    res.json({
      totalProducts,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/products/stats/top-expensive", async (req, res, next) => {
  try {
    const limit = req.query.limit === undefined ? 3 : Number(req.query.limit);

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      const error = new Error("limit must be an integer between 1 and 100");
      error.statusCode = 400;
      throw error;
    }

    const result = await getCollection()
      .aggregate([
      { $sort: { price: -1 } },
      { $limit: limit },
    ])
      .toArray();

    res.json(result.map(serializeItem));
  } catch (error) {
    next(error);
  }
});

app.get("/products/stats/average-price", async (_req, res, next) => {
  try {
    const result = await getCollection()
      .aggregate([
        {
          $group: {
            _id: null,
            averagePrice: { $avg: "$price" },
            totalProducts: { $sum: 1 },
          },
        },
      ])
      .toArray();

    const stats = result[0] || {
      averagePrice: 0,
      totalProducts: 0,
    };

    res.json({
      averagePrice: stats.averagePrice,
      totalProducts: stats.totalProducts,
    });
  } catch (error) {
    next(error);
  }
});

// Register the same CRUD behavior for both /products and /api/items.
for (const basePath of RESOURCE_PATHS) {
  app.get(basePath, async (req, res, next) => {
    try {
      // Filtering, sorting, pagination, and cursor mode are all resolved from query params.
      const filter = buildFilterQuery(req.query);
      const listOptions = buildListOptions(req.query);
      const [items, total] = await Promise.all([
        listItems(filter, listOptions),
        countItems(filter),
      ]);
      const nextCursor = items.length === listOptions.limit ? String(items[items.length - 1]._id) : null;
      const serializedItems = items.map(serializeItem);

      res.json({
        data: serializedItems,
        pagination: {
          total,
          page: listOptions.page,
          limit: listOptions.limit,
          totalPages: Math.max(1, Math.ceil(total / listOptions.limit)),
          nextCursor,
          cursorMode: Boolean(listOptions.cursor),
        },
        sort: {
          sortBy: listOptions.sortBy,
          order: listOptions.order,
        },
      });
    } catch (error) {
      next(error);
    }
  });

  app.get(`${basePath}/:id`, async (req, res, next) => {
    try {
      const item = await findItemById(req.params.id);

      if (!item) {
        return res.status(404).json({ error: "Item not found" });
      }

      res.json(serializeItem(item));
    } catch (error) {
      next(error);
    }
  });

  app.post(basePath, requireStaff, async (req, res, next) => {
    try {
      const payload = validateItemPayload(req.body);
      const item = await createItem(payload);
      res.status(201).json(serializeItem(item));
    } catch (error) {
      next(error);
    }
  });

  app.post(`${basePath}/bulk`, requireStaff, async (req, res, next) => {
    try {
      const operations = Array.isArray(req.body) ? req.body : req.body?.operations;

      if (!Array.isArray(operations) || operations.length === 0) {
        const error = new Error("operations must be a non-empty array");
        error.statusCode = 400;
        throw error;
      }

      if (operations.length > MAX_BULK_OPERATIONS) {
        const error = new Error(`operations cannot exceed ${MAX_BULK_OPERATIONS} items`);
        error.statusCode = 400;
        throw error;
      }

      const ordered =
        Array.isArray(req.body) || req.body?.ordered === undefined ? false : Boolean(req.body.ordered);
      const result = await runBulkOperations(operations, ordered);

      res.status(200).json({
        acknowledged: result.acknowledged ?? true,
        ordered,
        insertedCount: result.insertedCount,
        matchedCount: result.matchedCount,
        modifiedCount: result.modifiedCount,
        deletedCount: result.deletedCount,
        upsertedCount: result.upsertedCount,
      });
    } catch (error) {
      next(error);
    }
  });

  app.put(`${basePath}/:id`, requireStaff, async (req, res, next) => {
    try {
      const payload = validateItemPayload(req.body);
      const item = await updateItem(req.params.id, payload);

      if (!item) {
        return res.status(404).json({ error: "Item not found" });
      }

      res.json(serializeItem(item));
    } catch (error) {
      next(error);
    }
  });

  app.patch(`${basePath}/:id`, requireStaff, async (req, res, next) => {
    try {
      const payload = validatePartialItemPayload(req.body);
      const item = await patchItem(req.params.id, payload);

      if (!item) {
        return res.status(404).json({ error: "Item not found" });
      }

      res.json(serializeItem(item));
    } catch (error) {
      next(error);
    }
  });

  app.delete(`${basePath}/:id`, requireStaff, async (req, res, next) => {
    try {
      const item = await deleteItem(req.params.id);

      if (!item) {
        return res.status(404).json({ error: "Item not found" });
      }

      res.json({
        message: "Item deleted successfully",
        item: serializeItem(item),
      });
    } catch (error) {
      next(error);
    }
  });
}

// Friendly HTML entry points for faster navigation.
app.get("/", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "admin-login.html"));
});

app.get("/worker", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "worker-login.html"));
});

app.get("/shop", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "user-login.html"));
});

app.get("/register", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "user-register.html"));
});

// Orders for user checkout.
app.get("/orders", requireUser, async (req, res, next) => {
  try {
    const orders = await getOrdersCollection()
      .find({ userId: req.user.id })
      .sort({ createdAt: -1, _id: -1 })
      .toArray();

    res.json({
      data: orders,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/orders", requireUser, async (req, res, next) => {
  try {
    const payload = validateOrderPayload(req.body);
    const requestedItems = payload.items;
    const productIds = requestedItems.map((item) => parseObjectId(item.productId));
    const products = await getCollection()
      .find({ _id: { $in: productIds } })
      .toArray();

    const productMap = new Map(products.map((product) => [String(product._id), product]));

    const lineItems = requestedItems.map((item) => {
      const product = productMap.get(item.productId);

      if (!product) {
        const error = new Error("One or more products were not found");
        error.statusCode = 404;
        throw error;
      }

      if (product.quantity < item.quantity) {
        const error = new Error(`Insufficient stock for ${product.name}`);
        error.statusCode = 400;
        throw error;
      }

      return {
        productId: item.productId,
        name: product.name,
        price: product.price,
        quantity: item.quantity,
        lineTotal: Number(product.price) * item.quantity,
      };
    });

    const now = new Date();
    const bulkUpdates = lineItems.map((item) => ({
      updateOne: {
        filter: { _id: parseObjectId(item.productId) },
        update: {
          $inc: { quantity: -item.quantity },
          $set: { updatedAt: now },
        },
      },
    }));

    if (bulkUpdates.length > 0) {
      await getCollection().bulkWrite(bulkUpdates, { ordered: true });
    }

    const order = {
      userId: req.user.id,
      username: req.user.username,
      items: lineItems,
      subtotal: lineItems.reduce((sum, item) => sum + item.lineTotal, 0),
      totalItems: lineItems.reduce((sum, item) => sum + item.quantity, 0),
      status: "placed",
      approvedAt: null,
      approvedBy: null,
      cancelledAt: null,
      cancelledBy: null,
      refundedAt: null,
      refundedBy: null,
      reopenedAt: null,
      reopenedBy: null,
      note: payload.note,
      createdAt: now,
    };

    const result = await getOrdersCollection().insertOne(order);
    const createdOrder = await getOrdersCollection().findOne({ _id: result.insertedId });

    res.status(201).json(createdOrder);
  } catch (error) {
    next(error);
  }
});

app.post("/orders/:id/cancel", requireUser, async (req, res, next) => {
  try {
    const orderId = parseObjectId(req.params.id);
    const order = await getOrdersCollection().findOne({ _id: orderId, userId: req.user.id });

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (order.status === "approved") {
      const error = new Error("Approved orders cannot be cancelled");
      error.statusCode = 400;
      throw error;
    }

    if (order.status === "refunded") {
      const error = new Error("Refunded orders cannot be cancelled");
      error.statusCode = 400;
      throw error;
    }

    if (order.status === "cancelled") {
      return res.json({ message: "Order is already cancelled", order });
    }

    const now = new Date();
    await getOrdersCollection().updateOne(
      { _id: orderId },
      {
        $set: {
          status: "cancelled",
          cancelledAt: now,
          cancelledBy: req.user.username,
        },
      }
    );

    const restockOps = (order.items || []).map((item) => ({
      updateOne: {
        filter: { _id: parseObjectId(item.productId) },
        update: {
          $inc: { quantity: item.quantity },
          $set: { updatedAt: now },
        },
      },
    }));

    if (restockOps.length > 0) {
      await getCollection().bulkWrite(restockOps, { ordered: true });
    }

    const updatedOrder = await getOrdersCollection().findOne({ _id: orderId });

    res.json({
      message: "Order cancelled",
      order: updatedOrder,
    });
  } catch (error) {
    next(error);
  }
});

// Fallback and centralized error handling.
app.use((req, res) => {
  res.status(404).json({
    error: `Endpoint not found: ${req.method} ${req.originalUrl}`,
  });
});

app.use((error, _req, res, _next) => {
  const statusCode = error.type === "entity.parse.failed" ? 400 : error.statusCode || 500;
  const message =
    error.type === "entity.parse.failed"
      ? "Request body contains invalid JSON"
      : error.message || "Internal server error";

  res.status(statusCode).json({
    error: message,
  });
});

// Validation helpers.
function parseImageDataUrl(value) {
  const match = value.match(/^data:([^;]+);base64,(.+)$/);

  if (!match) {
    const error = new Error("image must be a base64 data URL");
    error.statusCode = 400;
    throw error;
  }

  const mimeType = match[1].toLowerCase();

  if (!ALLOWED_IMAGE_MIME.has(mimeType)) {
    const error = new Error("image type must be JPEG, PNG, or WEBP");
    error.statusCode = 400;
    throw error;
  }

  let buffer;

  try {
    buffer = Buffer.from(match[2], "base64");
  } catch (_error) {
    const error = new Error("image must be valid base64 data");
    error.statusCode = 400;
    throw error;
  }

  if (!buffer.length) {
    const error = new Error("image cannot be empty");
    error.statusCode = 400;
    throw error;
  }

  if (buffer.length > MAX_IMAGE_BYTES) {
    const error = new Error(`image must be smaller than ${Math.round(MAX_IMAGE_BYTES / 1024 / 1024)}MB`);
    error.statusCode = 400;
    throw error;
  }

  return {
    data: buffer,
    mimeType,
    size: buffer.length,
  };
}

function parseImagePayload(value) {
  if (value === undefined) {
    return undefined;
  }

  if (value === null || value === "") {
    return null;
  }

  if (typeof value !== "string") {
    const error = new Error("image must be a base64 data URL string");
    error.statusCode = 400;
    throw error;
  }

  return parseImageDataUrl(value);
}

function validateItemPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Request body must be a JSON object");
    error.statusCode = 400;
    throw error;
  }

  const name = String(body.name || "").trim();
  const quantity = Number(body.quantity);
  const price = Number(body.price);
  const image = parseImagePayload(body.image);

  if (!name) {
    const error = new Error("name is required");
    error.statusCode = 400;
    throw error;
  }

  if (!Number.isFinite(quantity) || quantity < 0) {
    const error = new Error("quantity must be a number greater than or equal to 0");
    error.statusCode = 400;
    throw error;
  }

  if (!Number.isFinite(price) || price < 0) {
    const error = new Error("price must be a number greater than or equal to 0");
    error.statusCode = 400;
    throw error;
  }

  const payload = {
    name,
    quantity,
    price,
    description: typeof body.description === "string" ? body.description.trim() : "",
  };

  if (image !== undefined) {
    payload.image = image;
  }

  return payload;
}

// Admin registration/login validation.
function validateAdminCredentials(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Request body must be a JSON object");
    error.statusCode = 400;
    throw error;
  }

  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!username || username.length < 3) {
    const error = new Error("username must be at least 3 characters");
    error.statusCode = 400;
    throw error;
  }

  if (!password || password.length < 6) {
    const error = new Error("password must be at least 6 characters");
    error.statusCode = 400;
    throw error;
  }

  return { username, password };
}

// Admin account updates require the current password plus at least one new value.
function validateAdminUpdatePayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Request body must be a JSON object");
    error.statusCode = 400;
    throw error;
  }

  const currentPassword = String(body.currentPassword || "");
  const username =
    body.username === undefined ? undefined : String(body.username || "").trim().toLowerCase();
  const newPassword = body.newPassword === undefined ? "" : String(body.newPassword || "");

  if (!currentPassword || currentPassword.length < 6) {
    const error = new Error("currentPassword must be at least 6 characters");
    error.statusCode = 400;
    throw error;
  }

  if (username !== undefined && username.length < 3) {
    const error = new Error("username must be at least 3 characters");
    error.statusCode = 400;
    throw error;
  }

  if (newPassword && newPassword.length < 6) {
    const error = new Error("newPassword must be at least 6 characters");
    error.statusCode = 400;
    throw error;
  }

  if (username === undefined && !newPassword) {
    const error = new Error("Provide a new username or new password to update your account");
    error.statusCode = 400;
    throw error;
  }

  return {
    username,
    currentPassword,
    newPassword,
  };
}

// PATCH accepts only the fields provided, but still validates each one.
function validatePartialItemPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Request body must be a JSON object");
    error.statusCode = 400;
    throw error;
  }

  const payload = {};

  if (body.name !== undefined) {
    const name = String(body.name).trim();

    if (!name) {
      const error = new Error("name cannot be empty");
      error.statusCode = 400;
      throw error;
    }

    payload.name = name;
  }

  if (body.quantity !== undefined) {
    const quantity = Number(body.quantity);

    if (!Number.isFinite(quantity) || quantity < 0) {
      const error = new Error("quantity must be a number greater than or equal to 0");
      error.statusCode = 400;
      throw error;
    }

    payload.quantity = quantity;
  }

  if (body.price !== undefined) {
    const price = Number(body.price);

    if (!Number.isFinite(price) || price < 0) {
      const error = new Error("price must be a number greater than or equal to 0");
      error.statusCode = 400;
      throw error;
    }

    payload.price = price;
  }

  if (body.description !== undefined) {
    payload.description = typeof body.description === "string" ? body.description.trim() : "";
  }

  if (body.image !== undefined) {
    payload.image = parseImagePayload(body.image);
  }

  if (Object.keys(payload).length === 0) {
    const error = new Error("At least one valid field is required for PATCH");
    error.statusCode = 400;
    throw error;
  }

  return payload;
}

function validateOrderPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Request body must be a JSON object");
    error.statusCode = 400;
    throw error;
  }

  const items = Array.isArray(body.items) ? body.items : [];

  if (items.length === 0) {
    const error = new Error("items must be a non-empty array");
    error.statusCode = 400;
    throw error;
  }

  const parsedItems = items.map((item, index) => {
    if (!item || typeof item !== "object") {
      const error = new Error(`items[${index}] must be an object`);
      error.statusCode = 400;
      throw error;
    }

    const productId = String(item.productId || item.id || "").trim();
    const quantity = Number(item.quantity);

    if (!productId || !ObjectId.isValid(productId)) {
      const error = new Error(`items[${index}].productId must be a valid id`);
      error.statusCode = 400;
      throw error;
    }

    if (!Number.isInteger(quantity) || quantity < 1) {
      const error = new Error(`items[${index}].quantity must be an integer >= 1`);
      error.statusCode = 400;
      throw error;
    }

    return {
      productId,
      quantity,
    };
  });

  return {
    items: parsedItems,
    note: typeof body.note === "string" ? body.note.trim() : "",
  };
}

// Query parsing helpers for filtering, sorting, and pagination.
function buildFilterQuery(query) {
  const filter = {};
  const entries = Object.entries(query || {});

  for (const [rawKey, rawValue] of entries) {
    const parsed = parseFilterKey(rawKey, rawValue);

    if (!parsed) {
      continue;
    }

    const { field, operator, value } = parsed;

    if (!filter[field] || typeof filter[field] !== "object" || Array.isArray(filter[field])) {
      filter[field] = {};
    }

    filter[field][operator] = value;
  }

  return filter;
}

function buildListOptions(query) {
  const allowedSortFields = new Set(["name", "price", "quantity", "createdAt", "updatedAt"]);
  const sortBy = typeof query.sortBy === "string" ? query.sortBy : "createdAt";
  const order = typeof query.order === "string" ? query.order.toLowerCase() : "desc";
  const page = query.page === undefined ? 1 : Number(query.page);
  const limit = query.limit === undefined ? 20 : Number(query.limit);
  const cursor = typeof query.cursor === "string" ? query.cursor : null;

  if (!allowedSortFields.has(sortBy)) {
    const error = new Error(`sortBy must be one of: ${Array.from(allowedSortFields).join(", ")}`);
    error.statusCode = 400;
    throw error;
  }

  if (!["asc", "desc"].includes(order)) {
    const error = new Error('order must be either "asc" or "desc"');
    error.statusCode = 400;
    throw error;
  }

  if (!Number.isInteger(page) || page < 1) {
    const error = new Error("page must be an integer greater than or equal to 1");
    error.statusCode = 400;
    throw error;
  }

  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    const error = new Error("limit must be an integer between 1 and 100");
    error.statusCode = 400;
    throw error;
  }

  if (cursor && !ObjectId.isValid(cursor)) {
    const error = new Error("cursor must be a valid item id");
    error.statusCode = 400;
    throw error;
  }

  if (cursor && query.page !== undefined) {
    const error = new Error("cursor pagination cannot be combined with page");
    error.statusCode = 400;
    throw error;
  }

  if (cursor && (sortBy !== "createdAt" || order !== "desc")) {
    const error = new Error('cursor pagination currently supports only sortBy=createdAt&order=desc');
    error.statusCode = 400;
    throw error;
  }

  return {
    page,
    limit,
    cursor,
    sortBy,
    order,
    sort: {
      [sortBy]: order === "asc" ? 1 : -1,
      _id: order === "asc" ? 1 : -1,
    },
  };
}

// Supports both bracket syntax like price[$gte]=10 and parsed nested query objects.
function parseFilterKey(rawKey, rawValue) {
  const nestedValue =
    rawValue && typeof rawValue === "object" && !Array.isArray(rawValue) ? rawValue : null;

  if (nestedValue) {
    const operators = Object.entries(nestedValue);

    if (operators.length !== 1) {
      const error = new Error(`Invalid filter format for "${rawKey}"`);
      error.statusCode = 400;
      throw error;
    }

    const [operator, value] = operators[0];
    return normalizeFilter(rawKey, operator, value);
  }

  const match = rawKey.match(/^([a-zA-Z0-9_]+)\[(\$gte|\$lte|\$regex)\]$/);

  if (!match) {
    return null;
  }

  const [, field, operator] = match;
  return normalizeFilter(field, operator, rawValue);
}

function normalizeFilter(field, operator, rawValue) {
  const numericFields = new Set(["price", "quantity"]);
  const regexFields = new Set(["name", "description"]);

  if (!["$gte", "$lte", "$regex"].includes(operator)) {
    const error = new Error(`Unsupported operator "${operator}"`);
    error.statusCode = 400;
    throw error;
  }

  if ((operator === "$gte" || operator === "$lte") && !numericFields.has(field)) {
    const error = new Error(`${operator} is only supported for price and quantity`);
    error.statusCode = 400;
    throw error;
  }

  if (operator === "$regex" && !regexFields.has(field)) {
    const error = new Error(`$regex is only supported for name and description`);
    error.statusCode = 400;
    throw error;
  }

  if (operator === "$regex") {
    return {
      field,
      operator,
      value: new RegExp(String(rawValue), "i"),
    };
  }

  const numericValue = Number(rawValue);

  if (!Number.isFinite(numericValue)) {
    const error = new Error(`${field} ${operator} value must be a valid number`);
    error.statusCode = 400;
    throw error;
  }

  return {
    field,
    operator,
    value: numericValue,
  };
}

// Validates ids before they reach MongoDB calls.
function parseObjectId(id) {
  if (!ObjectId.isValid(id)) {
    const error = new Error("Invalid item id");
    error.statusCode = 400;
    throw error;
  }

  return new ObjectId(id);
}

// MongoDB connection and index creation.
async function connectToDatabase() {
  if (!MONGO_URI) {
    console.warn("MONGO_URI is missing in .env. API endpoints will return 503 until it is set.");
    return;
  }

  client = new MongoClient(MONGO_URI, {
    maxPoolSize: 10,
    minPoolSize: 1,
    retryWrites: true,
    serverSelectionTimeoutMS: 10000,
  });

  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    collection = client.db(DB_NAME).collection(COLLECTION_NAME);
    adminsCollection = client.db(DB_NAME).collection(ADMINS_COLLECTION_NAME);
    workersCollection = client.db(DB_NAME).collection(WORKERS_COLLECTION_NAME);
    usersCollection = client.db(DB_NAME).collection(USERS_COLLECTION_NAME);
    ordersCollection = client.db(DB_NAME).collection(ORDERS_COLLECTION_NAME);
    // Indexes support the filters, sorting, and admin lookups used by the API.
    await collection.createIndexes([
      { key: { name: 1 } },
      { key: { price: 1 } },
      { key: { quantity: 1 } },
      { key: { createdAt: -1 } },
      { key: { updatedAt: -1 } },
      { key: { name: "text", description: "text" } },
    ]);
    await adminsCollection.createIndexes([
      { key: { username: 1 }, unique: true },
      { key: { createdAt: -1 } },
    ]);
    await workersCollection.createIndexes([
      { key: { username: 1 }, unique: true },
      { key: { createdAt: -1 } },
    ]);
    await usersCollection.createIndexes([
      { key: { username: 1 }, unique: true },
      { key: { createdAt: -1 } },
      { key: { provider: 1, providerId: 1 } },
      { key: { email: 1 } },
    ]);
    await ordersCollection.createIndexes([
      { key: { userId: 1 } },
      { key: { createdAt: -1 } },
    ]);
    console.log(`MongoDB connected successfully to ${DB_NAME}.${COLLECTION_NAME}`);
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
  }
}

// Graceful shutdown closes both the HTTP server and MongoDB client.
async function shutdown(signal) {
  console.log(`${signal} received. Shutting down gracefully.`);

  if (server) {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }

  if (client) {
    await client.close();
  }

  process.exit(0);
}

// Process signal handlers.
process.on("SIGINT", () => {
  shutdown("SIGINT").catch((error) => {
    console.error("Error during shutdown:", error.message);
    process.exit(1);
  });
});

process.on("SIGTERM", () => {
  shutdown("SIGTERM").catch((error) => {
    console.error("Error during shutdown:", error.message);
    process.exit(1);
  });
});

// Application bootstrap.
async function startServer() {
  await connectToDatabase();

  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server failed to start:", error.message);
  process.exit(1);
});
