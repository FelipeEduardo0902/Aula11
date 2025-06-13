const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de segurança
app.use(helmet()); // Adiciona headers de segurança (slide 25)
app.use(cors());   // Protege contra alguns ataques de CORS (slide 25)
app.use(express.json());

// Limitação de requisições (rate limiting, slide 6)
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10 // máximo de 10 requisições por minuto por IP
});
app.use(limiter);

// Simulação de "banco" de usuários (slide: não precisa banco real)
const usuarios = [
  {
    id: 1,
    email: 'usuario@exemplo.com',
    senha: bcrypt.hashSync('123456', 10)
  }
];

// Rota de login (slide 19)
app.post('/login', (req, res) => {
  const { email, senha } = req.body;
  const usuario = usuarios.find(u => u.email === email);
  if (!usuario) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });

  const senhaValida = bcrypt.compareSync(senha, usuario.senha);
  if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });

  // Geração do token JWT (slide 21)
  const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware para proteger rotas (slide 20, 22)
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  if (!token) return res.status(401).json({ erro: 'Token não enviado' });

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ erro: 'Token inválido ou expirado' });
    req.usuario = usuario;
    next();
  });
}

// Rota protegida (slide 27/28)
app.get('/protegido', autenticarToken, (req, res) => {
  res.json({ mensagem: `Bem-vindo, usuário ${req.usuario.email}!`, dados: req.usuario });
});

// Endpoint para renovar token (refresh)
app.post('/reauth', autenticarToken, (req, res) => {
  const { id, email } = req.usuario;
  const novoToken = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token: novoToken });
});

// Boas práticas: resposta para rota não encontrada
app.use((req, res) => {
  res.status(404).json({ erro: 'Rota não encontrada' });
});

app.listen(PORT, () => {
  console.log(`API segura rodando na porta ${PORT}`);
});
