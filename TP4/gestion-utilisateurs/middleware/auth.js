const pool = require('../database/db');

async function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'Token inexistant / introuvable' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Vérifier que le token est valide
        const result = await client.query(
            `SELECT s.id AS session_id, s.utilisateur_id, s.date_expiration, s.actif AS session_active,
                    u.id, u.email, u.nom, u.prenom, u.actif AS user_actif
             FROM sessions s
             JOIN utilisateurs u ON u.id = s.utilisateur_id
             WHERE s.token = $1
               AND s.actif = TRUE
               AND u.actif = TRUE
               AND (s.date_expiration IS NULL OR s.date_expiration > NOW())`,
            [token]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        const user = result.rows[0];

        // Logger le succès de connexion
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, date_heure, adresse_ip, user_agent, succes, message)
             VALUES ($1, $2, NOW(), $3, $4, TRUE, $5)`,
            [
                user.utilisateur_id,
                user.email,
                req.ip || null,
                req.headers['user-agent'] || null,
                'Connexion réussie via middleware requireAuth'
            ]
        );

        await client.query('COMMIT');

        // Injecter les infos de l'utilisateur dans req
        req.user = {
            id: user.id,
            email: user.email,
            nom: user.nom,
            prenom: user.prenom
        };

        next();

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
}

module.exports = { requireAuth };
