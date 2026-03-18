const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const { initDatabase } = require('./config/database');
const { seedRuntimeData } = require('./config/runtimeSeed');

const app = express();
const PORT = process.env.PORT || 5000;
const API_BASE_PATH = normalizePath(process.env.API_BASE_PATH || '/api');
const PUBLIC_UPLOADS_BASE_PATH = normalizePath(process.env.PUBLIC_UPLOADS_BASE_PATH || '/uploads');

function normalizePath(value) {
  if (!value || value === '/') {
    return '/';
  }

  return `/${value.replace(/^\/+|\/+$/g, '')}`;
}

function joinPath(basePath, suffix) {
  const normalizedSuffix = suffix.startsWith('/') ? suffix : `/${suffix}`;

  if (basePath === '/') {
    return normalizedSuffix;
  }

  return `${basePath}${normalizedSuffix}`;
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(PUBLIC_UPLOADS_BASE_PATH, express.static(path.join(__dirname, '../uploads')));

const presignUrlsMiddleware = require('./middleware/presignUrls');
app.use(API_BASE_PATH, presignUrlsMiddleware);

app.use(joinPath(API_BASE_PATH, '/auth'), require('./routes/auth'));
app.use(joinPath(API_BASE_PATH, '/products'), require('./routes/products'));
app.use(joinPath(API_BASE_PATH, '/products/:id/reviews'), require('./routes/reviews'));
app.use(joinPath(API_BASE_PATH, '/cart'), require('./routes/cart'));
app.use(joinPath(API_BASE_PATH, '/orders'), require('./routes/orders'));
app.use(joinPath(API_BASE_PATH, '/upload'), require('./routes/upload'));

app.get(joinPath(API_BASE_PATH, '/health'), (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    config: {
      dbType: process.env.DB_TYPE || 'sqlite',
      storageType: process.env.STORAGE_TYPE || 'local',
      reviewStore: process.env.REVIEW_STORE || 'local',
      cacheType: process.env.CACHE_TYPE || 'memory',
      queueType: process.env.QUEUE_TYPE || 'sync',
    },
  });
});

app.get(joinPath(API_BASE_PATH, '/config'), (req, res) => {
  res.json({
    storageType: process.env.STORAGE_TYPE || 'local',
    reviewStore: process.env.REVIEW_STORE || 'local',
    dbType: process.env.DB_TYPE || 'sqlite',
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Requested resource was not found' });
});

app.use((err, req, res, next) => {
  console.error('[Error]', err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'An unexpected server error occurred',
  });
});

async function startServer() {
  try {
    await initDatabase();

    if ((process.env.AUTO_SEED_DATABASE || '').toLowerCase() === 'true') {
      await seedRuntimeData();
    }

    app.listen(PORT, () => {
      console.log('========================================');
      console.log('  Ecommerce API server started');
      console.log(`  Port: ${PORT}`);
      console.log(`  Base path: ${API_BASE_PATH}`);
      console.log(`  DB: ${process.env.DB_TYPE || 'sqlite'}`);
      console.log(`  Storage: ${process.env.STORAGE_TYPE || 'local'}`);
      console.log(`  Review store: ${process.env.REVIEW_STORE || 'local'}`);
      console.log(`  Cache: ${process.env.CACHE_TYPE || 'memory'}`);
      console.log(`  Queue: ${process.env.QUEUE_TYPE || 'sync'}`);
      console.log('========================================');
    });
  } catch (error) {
    console.error('[Server] Failed to start:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
