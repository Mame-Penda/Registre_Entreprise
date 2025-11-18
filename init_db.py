import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Récupérer DATABASE_URL
DATABASE_URL = os.environ.get('DATABASE_URL')

def init_database():
    """Initialise les tables de la base de données"""
    
    if DATABASE_URL:
        # PostgreSQL (Render)
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Table users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100),
                lastname VARCHAR(100),
                email VARCHAR(100) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table historique
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS historique (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR(100) NOT NULL,
                siret VARCHAR(14) NOT NULL,
                nom_entreprise VARCHAR(255),
                date_recherche TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table favoris
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favoris (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                siren VARCHAR(9) NOT NULL,
                nom_entreprise VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, siren)
            )
        """)
        
        # Table notes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Base de données PostgreSQL initialisée avec succès")
        
    else:
        # SQLite (développement local)
        import sqlite3
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Table users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100),
                lastname VARCHAR(100),
                email VARCHAR(100) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table historique
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS historique (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email VARCHAR(100) NOT NULL,
                siret VARCHAR(14) NOT NULL,
                nom_entreprise VARCHAR(255),
                date_recherche TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table favoris
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favoris (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                siren VARCHAR(9) NOT NULL,
                nom_entreprise VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, siren)
            )
        """)
        
        # Table notes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Base de données SQLite initialisée avec succès")


# N'exécuter que si appelé directement
if __name__ == "__main__":
    init_database()