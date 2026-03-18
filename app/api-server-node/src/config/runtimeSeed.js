const bcrypt = require('bcryptjs');
const { query } = require('./database');

const TEST_USER = {
  email: 'test@test.com',
  password: 'password123',
  name: '테스트유저',
};

const PRODUCT_CATEGORIES = ['전자기기', '패션', '식품', '생활용품', '뷰티'];

function buildDemoProducts() {
  const products = [];

  for (let index = 1; index <= 20; index += 1) {
    products.push({
      name: `Demo Product ${index}`,
      description: `Seeded demo product ${index} for cart and order persistence.`,
      price: 10000 + index * 1000,
      image_url: `/images/products/product-${index}.jpg`,
      category: PRODUCT_CATEGORIES[(index - 1) % PRODUCT_CATEGORIES.length],
      stock: 100,
    });
  }

  return products;
}

async function ensureTestUser() {
  const existingUsers = await query('SELECT id FROM users WHERE email = ?', [TEST_USER.email]);

  if (existingUsers.length > 0) {
    return false;
  }

  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(TEST_USER.password, salt);

  await query(
    'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)',
    [TEST_USER.email, passwordHash, TEST_USER.name]
  );

  return true;
}

async function ensureProducts() {
  const existingProducts = await query('SELECT COUNT(*) as count FROM products', []);
  const productCount = existingProducts[0].count;

  if (productCount > 0) {
    return 0;
  }

  const products = buildDemoProducts();

  for (const product of products) {
    await query(
      `INSERT INTO products (name, description, price, image_url, category, stock)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [product.name, product.description, product.price, product.image_url, product.category, product.stock]
    );
  }

  return products.length;
}

async function seedRuntimeData() {
  const userCreated = await ensureTestUser();
  const productsSeeded = await ensureProducts();

  if (userCreated || productsSeeded > 0) {
    console.log('[Seed] Runtime seed applied', {
      userCreated,
      productsSeeded,
    });
  } else {
    console.log('[Seed] Runtime seed skipped because data already exists');
  }
}

module.exports = { seedRuntimeData };
