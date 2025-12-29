const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');

// Route pour lister les utilisateurs (admin seulement)
router.get('/', authenticate, authorizeAdmin, async (req, res) => {
  // Ne pas exposer les mots de passe
  const sql = 'SELECT id, username, email, role, created_at FROM users';
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des utilisateurs :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

// Route pour récupérer un utilisateur spécifique
router.get('/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  // Vérifier que l'utilisateur accède à son propre profil ou est admin
  if (parseInt(id) !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès non autorisé' });
  }

  // Ne pas exposer le mot de passe
  const sql = 'SELECT id, username, email, role, created_at FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'utilisateur' });
  }
});

// Route pour supprimer un utilisateur (admin seulement)
router.delete('/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  // Empêcher un admin de se supprimer lui-même
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas vous supprimer vous-même' });
  }

  const sql = 'DELETE FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur' });
  }
});

// Route pour modifier un utilisateur
router.put('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { username, email, password } = req.body;

  // Vérifier que l'utilisateur modifie son propre profil ou est admin
  if (parseInt(id) !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès non autorisé' });
  }

  // Empêcher la modification du rôle par un utilisateur non-admin
  // Seuls les admins peuvent modifier les rôles via une route dédiée
  const sql = 'UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [username, email, password, id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    // Ne pas exposer le mot de passe dans la réponse
    const newUser = { id, username, email, role: req.user.role };
    res.json({ message: 'Utilisateur modifié avec succès', user: newUser });
  } catch (err) {
    console.error('Erreur lors de la modification de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur' });
  }
});

// Route pour modifier le rôle d'un utilisateur (admin seulement)
router.put('/:id/role', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  // Validation du rôle
  if (!role || !['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide' });
  }

  // Empêcher un admin de modifier son propre rôle
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas modifier votre propre rôle' });
  }

  const sql = 'UPDATE users SET role = ? WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [role, id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json({ message: 'Rôle modifié avec succès' });
  } catch (err) {
    console.error('Erreur lors de la modification du rôle :', err);
    res.status(500).json({ error: 'Erreur lors de la modification du rôle' });
  }
});

module.exports = router;
