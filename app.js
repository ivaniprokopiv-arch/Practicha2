require('dotenv').config({ quiet: true });
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const storage = require('./dto/storage');

const app = express();
const PORT = process.env.PORT || 3111;

// ========== 1. MIDDLEWARE ==========
// Дозволяє читати JSON з тіла запиту (req.body)
app.use(express.json());

// Логер: друкує в терміналі кожен запит
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
  next(); // передаємо запит далі
});

// Перевірка JWT-токена
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  // 1. Чи є заголовок "Authorization: Bearer <токен>"?
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Авторизаційний токен відсутній (Bearer Token required)' });
  }

  // 2. Чи справжній токен і чи не прострочений?
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(403).json({ error: 'Токен недійсний або прострочений' });
  }

  next(); // усе добре — пускаємо далі
};

// Перевірка ролі користувача (RBAC)
const requireRole = (requiredRole) => {
  return (req, res, next) => {
    if (!req.user || req.user.role !== requiredRole) {
      return res.status(403).json({ error: `Доступ заборонено. Необхідна роль: ${requiredRole}` });
    }
    next();
  };
};

// ========== 2. МАРШРУТИ ==========
app.get('/', (req, res) => {
  res.json({ message: 'Сервер працює!' });
});

app.get('/users', authenticateJWT, requireRole('admin'), async (req, res) => {
  const users = await storage.getUsers();
  const safeUsers = users.map(({ passwordHash, ...u }) => u); // паролі ніколи не показуємо
  res.json(safeUsers);
});

app.get('/users/:id', authenticateJWT, async (req, res) => {
  const userData = await storage.findUserById(req.params.id);
  if (!userData) {
    return res.status(404).json({ error: 'Користувача не знайдено' });
  }
  res.json(userData);
});

app.post('/orders', authenticateJWT, async (req, res) => {
  const { product, amount } = req.body || {};
  if (!product || !amount) {
    return res.status(400).json({ error: "Поля product та amount є обов'язковими" });
  }

  const orders = await storage.getOrders();
  const newOrder = {
    id: storage.nextId(orders),
    userId: req.user.userId, // беремо з токена, а не з тіла запиту
    product,
    amount: Number(amount)
  };

  orders.push(newOrder);
  await storage.saveOrders(orders);
  res.status(201).json({ message: 'Замовлення успішно створено', order: newOrder });
});

app.post('/auth/register', async (req, res) => {
  const { username, password, name, role } = req.body || {};

  // 1. Перевіряємо обов'язкові поля
  if (!username || !password) {
    return res.status(400).json({ error: "Username та password є обов'язковими" });
  }

  // 2. Перевіряємо, чи такий username ще не зайнятий
  const existingUser = await storage.findUserByUsername(username);
  if (existingUser) {
    return res.status(400).json({ error: 'Користувач з таким username вже існує' });
  }

  // 3. Створюємо користувача з ХЕШОВАНИМ паролем
  const users = await storage.getUsers();
  const newUser = {
    id: storage.nextId(users),
    username,
    passwordHash: await bcrypt.hash(password, 10),
    name: name || username,
    role: role || 'user'
  };

  // 4. Зберігаємо у файл
  users.push(newUser);
  await storage.saveUsers(users);

  // 5. Повертаємо відповідь БЕЗ хешу пароля
  const { passwordHash, ...safeUser } = newUser;
  res.status(201).json({ message: 'Користувача успішно зареєстровано', user: safeUser });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Вкажіть username та password' });
  }

  // 1. Шукаємо користувача та порівнюємо пароль з хешем
  const user = await storage.findUserByUsername(username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Невірний логін або пароль' });
  }

  // 2. Створюємо JWT-токен
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );

  res.json({ message: 'Авторизація успішна', token });
});

// ========== 3. ОБРОБКА ПОМИЛОК ==========
// Маршрут не знайдено → 404
app.use((req, res) => {
  res.status(404).json({ error: `Маршрут ${req.method} ${req.url} не знайдено` });
});

// Будь-яка інша помилка → 500 (або 400 для зламаного JSON)
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.stack);
  res.status(err.status || 500).json({ error: 'Помилка під час обробки запиту', details: err.message });
});

// ========== 4. ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, () => {
  console.log(`Server is running at http://127.0.0.1:${PORT}`);
});