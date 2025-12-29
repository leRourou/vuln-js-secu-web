const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { generateToken } = require('../utils/jwt');

const SALT_ROUNDS = 10;

// Route pour s'inscrire
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Validation des entrées
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Tous les champs sont requis' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères' });
  }

  const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
  const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';

  try {
    const [existingUsers] = await req.db.execute(checkSql, [email, username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }

    // Hachage du mot de passe avec bcrypt
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const [results] = await req.db.execute(insertSql, [username, email, hashedPassword]);
    res.status(201).json({ message: 'Utilisateur créé avec succès', id: results.insertId });
  } catch (err) {
    console.error('Erreur lors de l\'inscription :', err);
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

// Route pour se connecter
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validation des entrées
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  const sql = 'SELECT * FROM users WHERE email = ?';

  try {
    const [results] = await req.db.execute(sql, [email]);
    if (results.length === 0) {
      // Message générique pour ne pas révéler si l'email existe
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const user = results[0];

    // Vérification du mot de passe avec bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = generateToken(user);

    // Ne pas retourner le mot de passe dans la réponse
    const { password: _, ...userWithoutPassword } = user;

    res.json({ message: 'Connexion réussie', token, user: userWithoutPassword });
  } catch (err) {
    console.error('Erreur lors de la connexion :', err);
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

module.exports = router;
