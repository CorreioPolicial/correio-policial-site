// Importa as ferramentas
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Configura a conexão com o banco de dados da Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Configurações do Servidor
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração da Sessão (para manter o usuário logado)
app.use(session({
  secret: process.env.SESSION_SECRET || 'um-segredo-muito-dificil-de-adivinhar',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: 'auto' }
}));

// Middleware para disponibilizar informações do usuário para todas as páginas
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// --- ROTAS PÚBLICAS (qualquer um pode ver) ---

// Rota Principal (Homepage)
app.get('/', (req, res) => {
  res.render('pages/index');
});

// Rota da página de Cadastro
app.get('/register', (req, res) => {
  res.render('pages/register');
});

// Rota da página de Login
app.get('/login', (req, res) => {
  res.render('pages/login');
});

// --- ROTAS DE AÇÃO (processamento de formulários) ---

// Processar Cadastro
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.send('Usuário e senha são obrigatórios.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.send('Erro ao registrar. O nome de usuário pode já existir.');
  }
});

// Processar Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user; // Armazena todas as informações do usuário
      res.redirect('/painel');
    } else {
      res.send('Usuário ou senha inválidos.');
    }
  } catch (err) {
    console.error(err);
    res.send('Erro no login.');
  }
});

// Processar Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// --- ROTAS PRIVADAS (precisa estar logado) ---

// Middleware para checar se o usuário está logado
function checarLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Rota do Painel do Usuário
app.get('/painel', checarLogin, (req, res) => {
  res.render('pages/painel');
});


// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
