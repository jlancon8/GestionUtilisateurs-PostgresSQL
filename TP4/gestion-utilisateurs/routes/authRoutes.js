const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');

const bcrypt = require('bcrypt');

router.post('/register', async (req, res) => {
    const { email, password, nom, prenom } = req.body;

    // ptit controle de présence d'email et du mot de passe, le reste on s'en tape
    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe sont obligatoires' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // vérifie si l'email est sur la liste des invités
        const checkUser = await client.query(
            'SELECT id FROM utilisateurs WHERE email = $1',
            [email]
        );
        if (checkUser.rows.length > 0) {
            return res.status(409).json({ error: 'Email déjà utilisé' });
        }

        // Hashe le mot de passe a coup de hachette
        const passwordHash = await bcrypt.hash(password, 10);


        const result = await client.query(
            `INSERT INTO utilisateurs (email, password_hash, nom, prenom)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nom, prenom, date_creation`,
            [email, passwordHash, nom || null, prenom || null]
        );
        const newUser = result.rows[0];


        await client.query(
            `INSERT INTO utilisateur_roles (utilisateur_id, role_id)
       VALUES ($1, (SELECT id FROM roles WHERE nom = 'user'))`,
            [newUser.id]
        );

        await client.query('COMMIT');

        res.status(201).json({
            message: 'Utilisateur créé avec succès',
            user: newUser
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur création utilisateur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});


router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe sont obligatoires' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userResult = await client.query(
            'SELECT id, email, password_hash, nom, prenom, actif FROM utilisateurs WHERE email = $1',
            [email]
        );

        // Email non trouvé 😔
        if (userResult.rows.length === 0) {
            await client.query(
                `INSERT INTO logs_connexion (email_tentative, succes, message)
                 VALUES ($1, false, 'Email inconnu')`,
                [email]
            );
            await client.query('COMMIT');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const user = userResult.rows[0];

        if (!user.actif) {
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message)
                 VALUES ($1, $2, false, 'Utilisateur inactif')`,
                [user.id, email]
            );
            await client.query('COMMIT');
            return res.status(403).json({ error: 'Utilisateur inactif' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message)
                 VALUES ($1, $2, false, 'Mot de passe incorrect')`,
                [user.id, email]
            );
            await client.query('COMMIT');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const token = uuidv4();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        await client.query(
            `INSERT INTO sessions (utilisateur_id, token, date_expiration)
             VALUES ($1, $2, $3)`,
            [user.id, token, expiresAt]
        );

        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message)
             VALUES ($1, $2, true, 'Connexion réussie')`,
            [user.id, email]
        );

        await client.query('COMMIT');

        res.json({
            message: 'Connexion réussie',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                nom: user.nom,
                prenom: user.prenom
            },
            expiresAt: expiresAt
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});


router.get('/profile', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.email, u.nom, u.prenom,
                    array_agg(r.nom) AS roles
             FROM utilisateurs u
                      LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                      LEFT JOIN roles r ON ur.role_id = r.id
             WHERE u.id = $1
             GROUP BY u.id, u.email, u.nom, u.prenom`,
            [req.user.id]
        );

        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Erreur profil:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

module.exports = router;