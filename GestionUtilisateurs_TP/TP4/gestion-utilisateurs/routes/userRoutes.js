const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const {requireAuth, requirePermission} = require('../middleware/auth');

router.get('/', requireAuth, requirePermission('users', 'read'), async (req, res) => {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;
        try {
            const totalResult = await pool.query('SELECT COUNT(*) FROM users');
            const total = parseInt(totalResult.rows[0].count);

            const usersResult = await pool.query(`
                SELECT u.id, u.name, u.email, array_agg(r.name) AS roles
                FROM users u
                         LEFT JOIN user_roles ur ON u.id = ur.user_id
                         LEFT JOIN roles r ON ur.role_id = r.id
                GROUP BY u.id
                ORDER BY u.id
                    LIMIT $1
                OFFSET $2
            `, [limit, offset]);

            res.json({
                users: usersResult.rows,
                pagination: {
                    total,
                    page,
                    limit,
                    pages: Math.ceil(total / limit)
                }
            });
        } catch (error) {
            console.error('Erreur liste utilisateurs:', error);
            res.status(500).json({error: 'Erreur serveur'});
        }
    }
);



module.exports = router;
