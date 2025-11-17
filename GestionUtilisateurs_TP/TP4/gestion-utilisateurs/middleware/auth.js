const pool = require('../database/db');

async function requireAuth(req, res, next) {
    try {
        let token = req.headers['authorization'];
        console.log(token)
        if (!token) {
            return res.status(401).json({ error: 'Token manquant' });
        }
        token = token.replace(/^Bearer\s+/i, '').trim();

        const result = await pool.query(
            `SELECT s.id AS session_id, s.date_expiration, s.actif AS session_active,
                    u.id AS user_id, u.email, u.nom, u.prenom, u.actif AS user_active
             FROM sessions s
                      JOIN utilisateurs u ON s.utilisateur_id = u.id
             WHERE s.token = $1
               AND s.actif = TRUE
               AND s.date_expiration > NOW()
               AND u.actif = TRUE`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        req.user = {
            id: result.rows[0].user_id,
            email: result.rows[0].email,
            nom: result.rows[0].nom,
            prenom: result.rows[0].prenom
        };
        next();
    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}
async function requireAuthWithFunction(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        const validResult = await pool.query(
            'SELECT est_token_valide($1) AS valide',
            [token]
        );

        if (!validResult.rows[0].valide) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        const userResult = await pool.query(
            `SELECT s.utilisateur_id, u.email, u.nom, u.prenom
       FROM sessions s
       INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
       WHERE s.token = $1`,
            [token]
        );

        req.user = userResult.rows[0];
        next();
    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

function requirePermission(ressource, action) {
    return async (req, res, next) => {
        try {
            const result = await pool.query(
                'SELECT utilisateur_a_permission($1, $2, $3) AS a_permission',
                [req.user.utilisateur_id, ressource, action]
            );

            if (!result.rows[0].a_permission) {
                return res.status(403).json({ error: 'Permission refusée' });
            }

            next();
        } catch (error) {
            console.error('Erreur vérification permission:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    };
}


module.exports = { requireAuth, requireAuthWithFunction, requirePermission };
