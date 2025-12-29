const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');

// Route pour lister les commentaires d'un article
router.get('/articles/:id/comments', async (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM comments WHERE article_id = ?';
  console.log(sql);

  try {
    const [results] = await req.db.execute(sql, [id]);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des commentaires :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des commentaires' });
  }
});

// Route pour récupérer un commentaire spécifique
router.get('/comments/:id', async (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM comments WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      res.status(404).json({ error: 'Commentaire introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération du commentaire' });
  }
});

// Route pour ajouter un commentaire
router.post('/articles/:id/comments', authenticate, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  const user_id = req.user.id; // Utiliser l'ID de l'utilisateur authentifié

  // Validation de l'entrée
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'Le contenu du commentaire est requis' });
  }

  // Requête préparée pour éviter l'injection SQL
  const sql = 'INSERT INTO comments (user_id, article_id, content) VALUES (?, ?, ?)';

  try {
    const [results] = await req.db.execute(sql, [user_id, id, content]);
    const newComment = {
      id: results.insertId,
      content,
      user_id,
      article_id: id
    };
    res.status(201).json({ message: "Commentaire ajouté à l'article", comment: newComment });
  } catch (err) {
    console.error('Erreur lors de la création du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la création du commentaire' });
  }
});

// Route pour supprimer un commentaire
router.delete('/comments/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    // Vérifier que le commentaire existe
    const checkSql = 'SELECT * FROM comments WHERE id = ?';
    const [comments] = await req.db.execute(checkSql, [id]);

    if (comments.length === 0) {
      return res.status(404).json({ error: 'Commentaire introuvable' });
    }

    // Vérifier que l'utilisateur est l'auteur ou un admin
    if (comments[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Non autorisé à supprimer ce commentaire' });
    }

    const sql = 'DELETE FROM comments WHERE id = ?';
    await req.db.execute(sql, [id]);
    res.json({ message: 'Commentaire supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression du commentaire' });
  }
});

module.exports = router;
