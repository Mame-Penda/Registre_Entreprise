import os
import requests
import secrets
import json
import re
import traceback
from datetime import timedelta
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pymysql
import sys

# Active les logs détaillés
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

pymysql.install_as_MySQLdb()
load_dotenv()

# Configuration base de données
DATABASE_URL = os.environ.get('DATABASE_URL')

# Initialiser la base de données au démarrage
if DATABASE_URL:
    import psycopg2
    from init_db import init_database
    init_database()

    def get_db_connection():
        return psycopg2.connect(DATABASE_URL)
else:
    import sqlite3
    from init_db import init_database
    init_database()

    def get_db_connection():
        return sqlite3.connect("users.db")

app = Flask(__name__)
app.config['DEBUG'] = True
bcrypt = Bcrypt(app)

# Configuration session sécurisée
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre True en prod avec HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

CLIENT_ID = os.getenv("CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "").strip()
TOKEN_URL = "https://portail-api.insee.fr/token"
API_SIRENE_SIRET_URL = "https://api.insee.fr/api-sirene/3.11/siret/{siret}"

INSEE_API_KEY = os.getenv("INSEE_API_KEY", "").strip()

def insee_headers():
    return {
        "X-INSEE-Api-Key-Integration": INSEE_API_KEY,
        "Accept": "application/json",
    }

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")
mail = Mail(app)


def get_insee_token() -> str | None:
    if not CLIENT_ID or not CLIENT_SECRET:
        print("INSEE OAuth: CLIENT_ID/CLIENT_SECRET manquants")
        return None
    try:
        resp = requests.post(
            TOKEN_URL,
            data={"grant_type": "client_credentials"},
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            auth=(CLIENT_ID, CLIENT_SECRET),
            timeout=15,
        )
    except requests.RequestException as e:
        print(f"INSEE OAuth: erreur réseau : {e}")
        return None

    if not resp.ok:
        print(f"INSEE OAuth: HTTP {resp.status_code} – {resp.text[:200]}")
        return None

    try:
        payload = resp.json()
    except ValueError:
        print("INSEE OAuth: réponse non-JSON")
        return None

    return payload.get("access_token")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()
        if DATABASE_URL:
            cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], password):
            session["user"] = email
            session.permanent = True  # Session permanente
            return redirect(url_for("search_company"))
        else:
            return render_template("login.html", error="Identifiants incorrects.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        if not name or not re.match(r"^[a-zA-ZÀ-ÿ\s]+$", name):
            flash("Le nom doit contenir uniquement des lettres et des espaces.", "error")
            return render_template("register.html")
        if len(name) < 2 or len(name) > 50:
            flash("Le nom doit contenir entre 2 et 50 caractères.", "error")
            return render_template("register.html")

        lastname = request.form.get("lastname")
        if not lastname or not re.match(r"^[a-zA-ZÀ-ÿ\s]+$", lastname):
            flash("Le prénom doit contenir uniquement des lettres et des espaces.", "error")
            return render_template("register.html")
        if len(lastname) < 2 or len(lastname) > 50:
            flash("Le prénom doit contenir entre 2 et 50 caractères.", "error")
            return render_template("register.html")

        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            if DATABASE_URL:
                cursor.execute(
                    "INSERT INTO users (name, lastname, email, phone, password) VALUES (%s, %s, %s, %s, %s)",
                    (name, lastname, email, phone, hashed_pw)
                )
            else:
                cursor.execute(
                    "INSERT INTO users (name, lastname, email, phone, password) VALUES (?, ?, ?, ?, ?)",
                    (name, lastname, email, phone, hashed_pw)
                )
            conn.commit()
        except Exception:
            conn.close()
            flash("Ce numéro ou email est déjà utilisé.", "error")
            return render_template("register.html")

        conn.close()
        session["user"] = phone or email
        session.permanent = True  # Session permanente
        return redirect(url_for("search_company"))

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        conn = get_db_connection()
        cursor = conn.cursor()

        if DATABASE_URL:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template("forgot_password.html", error="Email introuvable.")

        token = secrets.token_urlsafe(32)
        session['reset_token'] = token
        session['reset_email'] = email
        reset_link = url_for("reset_password", token=token, _external=True)

        msg = Message("Réinitialisation de votre mot de passe", recipients=[email])
        msg.body = f"Bonjour,\n\nVoici votre lien pour réinitialiser le mot de passe : {reset_link}\n\nCe lien est temporaire."

        try:
            mail.send(msg)
            return render_template("forgot_password.html", message="Un lien a été envoyé à votre adresse email.")
        except Exception:
            return render_template("forgot_password.html", error="Erreur lors de l'envoi du mail.")

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") if request.method == "GET" else request.form.get("token")

    if session.get('reset_token') != token:
        return render_template("reset_password.html", error="Token invalide ou expiré.", token=token)

    if request.method == "POST":
        new_password = request.form.get("new_password")
        if new_password:
            hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
            email = session.get('reset_email')

            conn = get_db_connection()
            cursor = conn.cursor()

            if DATABASE_URL:
                cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
            else:
                cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email))

            conn.commit()
            conn.close()

            session.pop('reset_token', None)
            session.pop('reset_email', None)
            flash("Mot de passe modifié avec succès.")
            return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route('/articles')
def articles():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("articles.html")


@app.route('/about')
def about():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("about.html")


@app.route("/", methods=["GET", "POST"])
def search_company():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("search.html")

    siret = request.form.get("siret", "").strip()

    if not siret.isdigit() or len(siret) != 14:
        return render_template("search.html",
                               error="Numéro SIRET invalide. Il doit contenir 14 chiffres.")

    if not INSEE_API_KEY:
        return render_template("search.html",
                               error="INSEE_API_KEY manquant.")

    url = API_SIRENE_SIRET_URL.format(siret=siret)

    try:
        resp = requests.get(url, headers=insee_headers(), timeout=15)
    except requests.RequestException as e:
        return render_template("search.html",
                               error=f"Erreur de connexion à l'API INSEE : {e}")

    if resp.status_code != 200:
        return render_template("search.html",
                               error="Entreprise introuvable.")

    payload = resp.json()
    data = payload.get("etablissement") or payload.get("uniteLegale")

    if not data:
        return render_template("search.html", error="Réponse INSEE inattendue.")

    # Sauvegarde historique
    try:
        nom_entreprise = data.get("uniteLegale", {}).get("denominationUniteLegale", "Entreprise")
        user_email = session.get("user")

        conn = get_db_connection()
        cursor = conn.cursor()

        if DATABASE_URL:
            cursor.execute(
                "INSERT INTO historique (user_email, siret, nom_entreprise) VALUES (%s, %s, %s)",
                (user_email, siret, nom_entreprise)
            )
        else:
            cursor.execute(
                "INSERT INTO historique (user_email, siret, nom_entreprise) VALUES (?, ?, ?)",
                (user_email, siret, nom_entreprise)
            )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erreur historique: {e}")

    has_articles = 'articles' in app.view_functions
    return render_template("results.html", data=data, has_articles=has_articles)


@app.route("/bodacc", methods=["GET"])
def bodacc():
    try:
        if "user" not in session:
            return jsonify({"error": "Non authentifié"}), 401

        s = (request.args.get("siret") or request.args.get("siren") or "").strip()
        
        if not s:
            return jsonify({"error": "Paramètre manquant"}), 400

        if s.isdigit() and len(s) == 14:
            siren = s[:9]
        elif s.isdigit() and len(s) == 9:
            siren = s
        else:
            return jsonify({"error": "Numéro invalide"}), 400

        url = f"https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/?dataset=annonces-commerciales&q={siren}&rows=50"
        
        results = []
        
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        data = r.json()
        records = data.get("records", [])
        
        for rec in records:
            f = rec.get("fields", {})
            
            desc = f.get("modificationsgenerales", "")
            if desc:
                try:
                    j = json.loads(desc)
                    if isinstance(j, dict):
                        desc = " | ".join(f"{k}: {v}" for k, v in j.items())
                except:
                    pass
            else:
                desc = "N/A"
            
            results.append({
                "date_parution": f.get("dateparution", ""),
                "type_document": f.get("familleavis_lib", ""),
                "tribunal": f.get("tribunal", ""),
                "type_avis": f.get("typeavis_lib") or f.get("typeavis", ""),
                "reference": f.get("numeroannonce", ""),
                "description": desc,
                "pdf_url": f.get("urlpdf", ""),
            })
        
        return jsonify({"results": results})
        
    except Exception as e:
        print(f"ERREUR BODACC: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    
    user_email = session["user"]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    stats = {}
    
    if DATABASE_URL:
        cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_email = %s", (user_email,))
    else:
        cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_email = ?", (user_email,))
    stats['nb_favoris'] = cursor.fetchone()[0]
    
    if DATABASE_URL:
        cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = %s", (user_email,))
    else:
        cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = ?", (user_email,))
    stats['nb_recherches'] = cursor.fetchone()[0]
    
    if DATABASE_URL:
        cursor.execute(
            "SELECT siret, nom_entreprise, date_recherche FROM historique WHERE user_email = %s ORDER BY date_recherche DESC LIMIT 5",
            (user_email,)
        )
    else:
        cursor.execute(
            "SELECT siret, nom_entreprise, date_recherche FROM historique WHERE user_email = ? ORDER BY date_recherche DESC LIMIT 5",
            (user_email,)
        )
    dernieres_recherches = cursor.fetchall()
    
    conn.close()
    
    return render_template("dashboard.html", stats=stats, dernieres_recherches=dernieres_recherches)


@app.route("/mes_favoris", methods=["GET"])
def mes_favoris():
    if "user" not in session:
        return redirect(url_for("login"))
    
    user_email = session["user"]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_URL:
        cursor.execute(
            "SELECT siret, nom_entreprise, date_ajout FROM favoris WHERE user_email = %s ORDER BY date_ajout DESC",
            (user_email,)
        )
    else:
        cursor.execute(
            "SELECT siret, nom_entreprise, date_ajout FROM favoris WHERE user_email = ? ORDER BY date_ajout DESC",
            (user_email,)
        )
    
    favoris = cursor.fetchall()
    conn.close()
    
    return render_template("favoris.html", favoris=favoris)


@app.route("/ajouter_favori", methods=["POST"])
def ajouter_favori():
    if "user" not in session:
        return jsonify({"error": "Non authentifié"}), 401
    
    user_email = session["user"]
    siret = request.json.get("siret")
    nom_entreprise = request.json.get("nom_entreprise", "")
    
    if not siret:
        return jsonify({"error": "SIRET manquant"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if DATABASE_URL:
            cursor.execute(
                "INSERT INTO favoris (user_email, siret, nom_entreprise) VALUES (%s, %s, %s)",
                (user_email, siret, nom_entreprise)
            )
        else:
            cursor.execute(
                "INSERT INTO favoris (user_email, siret, nom_entreprise) VALUES (?, ?, ?)",
                (user_email, siret, nom_entreprise)
            )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Ajouté aux favoris"})
    except Exception:
        conn.close()
        return jsonify({"error": "Déjà dans les favoris"}), 400


@app.route("/supprimer_favori/<siret>", methods=["DELETE"])
def supprimer_favori(siret):
    if "user" not in session:
        return jsonify({"error": "Non authentifié"}), 401
    
    user_email = session["user"]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_URL:
        cursor.execute(
            "DELETE FROM favoris WHERE user_email = %s AND siret = %s",
            (user_email, siret)
        )
    else:
        cursor.execute(
            "DELETE FROM favoris WHERE user_email = ? AND siret = ?",
            (user_email, siret)
        )
    
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Supprimé"})


@app.route('/prospection', methods=['GET'])
def prospection():
    try:
        token = get_insee_token()
        if not token:
            flash("Impossible d'obtenir un token INSEE.", "error")
            return redirect(url_for("search_company"))
        
        url = "https://api.insee.fr/entreprises/sirene/V3/siren"
        codes_naf = ["6201Z", "6202A", "6202B"]
        naf_query = " OR ".join([f"activitePrincipaleUniteLegale:{code}" for code in codes_naf])
        query = f"periode({naf_query})"
        params = {"q": query, "nombre": 100}
        headers = {"Authorization": f"Bearer {token}"}
        
        resp = requests.get(url, headers=headers, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        
        entreprises = data.get("unitesLegales") or data.get("etablissements") or []
        results = []
        for ent in entreprises:
            results.append({
                "siren": ent.get("siren"),
                "nom": ent.get("denominationUniteLegale") or ent.get("nomUniteLegale"),
                "date_creation": ent.get("dateCreationUniteLegale"),
                "naf": ent.get("activitePrincipaleUniteLegale"),
            })
        return render_template("prospection.html", entreprises=results)
    except requests.RequestException as e:
        flash(f"Erreur API SIRENE : {e}", "error")
        return redirect(url_for("search_company"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)