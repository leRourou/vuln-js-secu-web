const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const initializeDbConnection = require('./db');

const app = express();

// Configuration de sécurité avec Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Pour DaisyUI/Tailwind
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "http://localhost:4000"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'no-referrer' },
}));

// Supprimer le header X-Powered-By
app.disable('x-powered-by');

// Configuration CORS sécurisée
const allowedOrigins = ['http://localhost:4000'];
app.use(cors({
  origin: function(origin, callback) {
    // Permettre les requêtes sans origin (comme curl, Postman)
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(bodyParser.json());

const startServer = async () => {
  try {
    // Attente que la base de données soit prête
    const db = await initializeDbConnection();
    console.log('Base de données initialisée avec succès.');

    // Injection de la connexion DB dans les routes
    app.use((req, res, next) => {
      req.db = db; // Ajout de la connexion à l'objet requête
      next();
    });

    // Importation des routes
    const authRoutes = require('./routes/auth');
    const userRoutes = require('./routes/users');
    const articleRoutes = require('./routes/articles');
    const commentRoutes = require('./routes/comments');

    // Utilisation des routes
    app.use('/api/auth', authRoutes);
    app.use('/api/users', userRoutes);
    app.use('/api/articles', articleRoutes);
    app.use('/api/', commentRoutes);

    const PORT = 5100;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

  } catch (error) {
    console.error('Erreur lors de l\'initialisation du serveur :', error);
    process.exit(1); // Arrêt en cas d'erreur critique
  }
};

startServer();