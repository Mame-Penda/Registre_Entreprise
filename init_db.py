import os
import psycopg2
import sqlite3

def init_database():
    """Initialise la base de données avec users, favoris et historique"""
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        print("❌ DATABASE_URL non définie. Utilisez SQLite en local.")
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Table users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                lastname TEXT NOT NULL,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        
        # Table favoris
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favoris (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                siret TEXT NOT NULL,
                nom_entreprise TEXT,
                date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_email, siret),
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        ''')
        
        # Table historique
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS historique (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                siret TEXT NOT NULL,
                nom_entreprise TEXT,
                date_recherche TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✓ Base de données SQLite initialisée (mode local)")
        return
    
    try:
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Table users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                lastname VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE,
                phone VARCHAR(20) UNIQUE,
                password VARCHAR(255) NOT NULL
            )
        ''')
        
        # Table favoris
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favoris (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                siret VARCHAR(14) NOT NULL,
                nom_entreprise TEXT,
                date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_email, siret),
                FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
            )
        ''')
        
        # Table historique
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS historique (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                siret VARCHAR(14) NOT NULL,
                nom_entreprise TEXT,
                date_recherche TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✓ Base de données PostgreSQL initialisée avec succès")
        
    except Exception as e:
        print(f"❌ Erreur initialisation PostgreSQL : {e}")
        raise

if __name__ == "__main__":
    init_database()