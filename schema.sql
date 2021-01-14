CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    hosts TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    session_token TEXT,
    FOREIGN KEY(user) REFERENCES users(login)
);

CREATE TABLE IF NOT EXISTS site_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    user_ID TEXT NOT NULL,
    password TEXT NOT NULL,
    FOREIGN KEY(user_ID) REFERENCES users(id)
);