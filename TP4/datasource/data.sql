DROP TABLE IF EXISTS logs_connexion CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS utilisateur_roles CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS utilisateurs CASCADE;


CREATE TABLE utilisateurs
(
    id                SERIAL PRIMARY KEY,
    email             VARCHAR(255) NOT NULL UNIQUE
        CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    password_hash     VARCHAR(255) NOT NULL,
    nom               VARCHAR(100),
    prenom            VARCHAR(100),
    actif             BOOLEAN   DEFAULT TRUE,
    date_creation     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_modification TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index pour recherche rapide
CREATE INDEX idx_utilisateurs_email ON utilisateurs (email);
CREATE INDEX idx_utilisateurs_actif ON utilisateurs (actif);

CREATE TABLE roles
(
    id            SERIAL PRIMARY KEY,
    nom           VARCHAR(255) UNIQUE,
    description   VARCHAR(255),
    date_creation date
);


CREATE TABLE permissions
(
    id          SERIAL PRIMARY KEY,
    nom         VARCHAR(255) UNIQUE,
    ressource   VARCHAR(255),
    action      VARCHAR(255),
    description VARCHAR(255),
    CONSTRAINT unique_ressource_action UNIQUE (ressource, action)
    -- contrainte unique
    -- empêche d'avoir deux fois la meme valeur dans deux lignes differente de ressource et action
);

CREATE TABLE utilisateur_roles
(
    utilisateur_id   INTEGER NOT NULL,
    role_id          INTEGER NOT NULL,
    date_assignation date,
    PRIMARY KEY (utilisateur_id, role_id),
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE role_permissions
(
    role_id       INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE sessions
(
    id              SERIAL PRIMARY KEY,
    utilisateur_id  INTEGER NOT NULL,
    token           VARCHAR(255) UNIQUE,
    date_creation   DATE,
    date_expiration DATE,
    actif           BOOLEAN,
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs (id)
);

CREATE TABLE logs_connexion
(
    id              SERIAL PRIMARY KEY,
    utilisateur_id  INTEGER,
    email_tentative VARCHAR(255),
    date_heure      DATE,
    adresse_ip      VARCHAR(50),
    user_agent      TEXT,
    succes         BOOLEAN,
    message         TEXT,
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs (id)
);


-- Insérer des rôles
INSERT INTO roles (nom, description)
VALUES ('admin', 'Administrateur avec tous les droits'),
       ('moderator', 'Modérateur de contenu'),
       ('user', 'Utilisateur standard');

-- Insérer des permissions
INSERT INTO permissions (nom, ressource, action, description)
VALUES ('read_users', 'users', 'read', 'Lire les utilisateurs'),
       ('write_users', 'users', 'write', 'Créer/modifier des utilisateurs'),
       ('delete_users', 'users', 'delete', 'Supprimer des utilisateurs'),
       ('read_posts', 'posts', 'read', 'Lire les posts'),
       ('write_posts', 'posts', 'write', 'Créer/modifier des posts'),
       ('delete_posts', 'posts', 'delete', 'Supprimer des posts');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON TRUE -- le on true permet de faire un produit carthesien de toute les lignes, donc avoir toute les permissions
WHERE r.nom = 'admin';


INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom = 'moderator'), id
FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts', 'delete_posts');


INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom = 'user'), id
FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts');


CREATE OR REPLACE FUNCTION utilisateur_a_permission(
    p_utilisateur_id INT,
    p_ressource VARCHAR,
    p_action VARCHAR
)
    RETURNS BOOLEAN AS
$$
BEGIN
    RETURN EXISTS ( -- return TRUE si au moins une ligne dans le renvoie
        SELECT 1
        FROM utilisateurs u
                 INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                 INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
                 INNER JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = p_utilisateur_id
          AND u.actif = true
          AND p.ressource = p_ressource
          AND p.action = p_action);
END;
$$ LANGUAGE plpgsql;


SELECT u.id,
       u.email,
       u.nom,
       u.prenom,
       u.actif,
       array_agg(r.nom) AS roles -- array_agg agrège tous les rôles dans un tableau
-- par exemple on pourra avoir {user, moderator}
FROM utilisateurs u
         INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         INNER JOIN roles r ON ur.role_id = r.id
WHERE u.id = 1
GROUP BY u.id, u.email, u.nom, u.prenom, u.actif;


SELECT DISTINCT
    u.id AS utilisateur_id,
    u.email,
    p.nom AS permission,
    p.ressource,
    p.action
FROM utilisateurs u
         INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
         INNER JOIN permissions p ON rp.permission_id = p.id
WHERE u.id = 1
ORDER BY p.ressource, p.action;


SELECT COUNT(ur.utilisateur_id) AS nombre_utilisateurs,
       r.nom AS role_nom
FROM roles r
LEFT JOIN utilisateur_roles ur ON r.id = ur.role_id
GROUP BY r.nom
ORDER BY nombre_utilisateurs DESC;


SELECT
    u.id,
    u.email,
    array_agg(r.nom) AS roles
FROM utilisateurs u
LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE r.nom IN ('admin', 'moderator')
GROUP BY u.id, u.email
HAVING COUNT(DISTINCT r.nom) = 2; -- s'assure que l'utilisateur a les deux rôles"


SELECT
    DATE(date_heure) AS jour,
    COUNT(*) AS tentatives_echouees
FROM logs_connexion
WHERE succes = false
  AND date_heure >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(date_heure)
ORDER BY jour DESC;


