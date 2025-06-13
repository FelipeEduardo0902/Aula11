const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Simulando um "banco" de usuários (1 usuário cadastrado)
const usuarios = [
  {
    id: 1,
    email: 'usuario@exemplo.com',
    senha: bcrypt.hashSync('123456', 10) // senha: 123456
  }
];

app.use(express.json());

// Rota pública de login
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const usuario = usuarios.find(u => u.email === email);
  if (!usuario) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });

  const senhaValida = await bcrypt.compare(senha, usuario.senha);
  if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });

  // Gera o token JWT
  const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

// Middleware para proteger rotas
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

// Rota protegida
app.get('/protegido', autenticarToken, (req, res) => {
  res.json({ mensagem: `Bem-vindo, usuário ${req.usuario.email}!`, dados: req.usuario });
});

// Rota para renovar token (reauth)
app.post('/reauth', autenticarToken, (req, res) => {
  const { id, email } = req.usuario;
  const novoToken = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token: novoToken });
});

// 404 genérico
app.use((req, res) => {
  res.status(404).json({ erro: 'Rota não encontrada' });
});

app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
