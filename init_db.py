import sqlite3
import os

def init_database():
    """Initialise la base de données avec la table users"""
    db_path = "users.db"
    
    # Crée le répertoire si nécessaire
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Création de la table users
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"✓ Base de données initialisée : {db_path}")

if __name__ == "__main__":
    init_database()