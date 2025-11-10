const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    name: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    dbport: process.env.DB_PORT,
    port: process.env.DB_PORT,
});
pool.on('connect', () => {
    console.log('✅ Connecté à PostgreSQL');
});
pool.on('error', (err) => {
    console.error('❌ Erreur PostgreSQL:', err);
});
module.exports = pool;
