import os
import sqlite3

# AJOUTEZ CECI TOUT EN HAUT, AVANT TOUT LE RESTE
def init_database():
    """Initialise la base de données avec la table users"""
    db_path = "users.db"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
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


init_database()

import base64
import requests
import secrets
import json
import re
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify