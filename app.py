import os
import base64
import requests
import secrets
import json
import re
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import pymysql

pymysql.install_as_MySQLdb()
load_dotenv()

# Configuration base de données
DATABASE_URL = os.environ.get('DATABASE_URL')

# Initialiser la base de données au démarrage
if DATABASE_URL:
    # Mode production avec PostgreSQL
    import psycopg2
    from init_db import init_database
    init_database()
    
    def get_db_connection():
        """Connexion PostgreSQL"""
        return psycopg2.connect(DATABASE_URL)
else:
    # Mode développement avec SQLite
    import sqlite3
    from init_db import init_database
    init_database()
    
    def get_db_connection():
        """Connexion SQLite (développement local)"""
        return sqlite3.connect("users.db")

app = Flask(__name__)
app.config['DEBUG'] = True
bcrypt = Bcrypt(app)
app.secret_key = secrets.token_hex(16)

CLIENT_ID = os.getenv("CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "").strip()
TOKEN_URL = "https://portail-api.insee.fr/token"
API_BASE = "https://api.insee.fr/api-sirene/3.11"
API_SIRENE_SIRET_URL = "https://api.insee.fr/api-sirene/3.11/siret/{siret}"
BODACC_API_URL = "https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/?dataset=annonces-commerciales&q="

INSEE_API_KEY = os.getenv("INSEE_API_KEY", "").strip()

def insee_headers():
    """Entêtes à utiliser pour appeler l'API Sirene avec la clé d'intégration."""
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
    """
    Récupère un access_token OAuth2 (client_credentials) côté INSEE.
    Retourne la chaîne du token, ou None en cas d'erreur.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        print("INSEE OAuth: CLIENT_ID/CLIENT_SECRET manquants")
        return None

    try:
        resp = requests.post(
            TOKEN_URL,
            data={"grant_type": "client_credentials"},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
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
        print(f"INSEE OAuth: réponse non-JSON ({resp.status_code})\n{resp.text[:200]}")
        return None

    token = payload.get("access_token")
    if not token:
        print(f"INSEE OAuth: pas d'access_token dans la réponse: {payload}")
        return None

    return token


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Utilise %s pour PostgreSQL, ? pour SQLite (géré automatiquement)
        if DATABASE_URL:
            cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
            
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[0], password):
            session["user"] = email
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
                # PostgreSQL
                cursor.execute(
                    "INSERT INTO users (name, lastname, email, phone, password) VALUES (%s, %s, %s, %s, %s)", 
                    (name, lastname, email, phone, hashed_pw)
                )
            else:
                # SQLite
                cursor.execute(
                    "INSERT INTO users (name, lastname, email, phone, password) VALUES (?, ?, ?, ?, ?)", 
                    (name, lastname, email, phone, hashed_pw)
                )
            conn.commit()
        except Exception as e:
            conn.close()
            flash("Ce numéro ou email est déjà utilisé.", "error")
            return render_template("register.html")
        
        conn.close()
        session["user"] = phone or email
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
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route('/articles')
def articles():
    """Page statique des articles."""
    return render_template("articles.html")


@app.route("/", methods=["GET", "POST"])
def search_company():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        siret = request.form.get("siret", "").strip()

        if not siret.isdigit() or len(siret) != 14:
            return render_template("search.html",
                                   error="Numéro SIRET invalide. Il doit contenir 14 chiffres.")

        if not INSEE_API_KEY:
            return render_template("search.html",
                                   error="INSEE_API_KEY manquant. Ajoutez-le dans votre .env puis redémarrez l'app.")

        url = API_SIRENE_SIRET_URL.format(siret=siret)
        try:
            resp = requests.get(url, headers=insee_headers(), timeout=15)
        except requests.RequestException as e:
            return render_template("search.html",
                                   error=f"Erreur de connexion à l'API INSEE : {e}")

        if resp.status_code == 200:
            payload = resp.json()
            data = payload.get("etablissement") or payload.get("uniteLegale")
            if not data:
                return render_template("search.html",
                                       error="Réponse INSEE inattendue.")
            has_articles = 'articles' in app.view_functions
            return render_template("results.html", data=data, has_articles=has_articles)

        elif resp.status_code == 404:
            return render_template("search.html", error="Établissement non trouvé.")

        else:
            try:
                err_json = resp.json()
                err_msg = err_json.get("message") or err_json
            except ValueError:
                err_msg = resp.text
            return render_template("search.html",
                                   error=f"Erreur API INSEE : {resp.status_code} – {err_msg}")

    return render_template("search.html")


def generate_pdf_url(annonce):
    """Construit une URL PDF BODACC robuste sans lever d'erreur 500."""

    publicationavis = annonce.get("publicationavis") or "A"
    parution = annonce.get("parution") or ""
    numerodossier = str(annonce.get("numerodossier") or "0")

    numero_annonce = annonce.get("numeroannonce")
    if numero_annonce is None or not str(numero_annonce).isdigit():
        numero_annonce_str = "00000"
    else:
        numero_annonce_str = str(numero_annonce).zfill(5)

    # Année sécurisée
    annee = parution[:4] if len(parution) >= 4 else "0000"

    base_url = (
        f"https://www.bodacc.fr/telechargements/COMMERCIALES/PDF/"
        f"{publicationavis}/{annee}/{parution}/"
    )

    # Première tentative : dossier réel
    url0 = (
        f"{base_url}{numerodossier}/"
        f"BODACC_{publicationavis}_PDF_Unitaire_{parution}_{numero_annonce_str}.pdf"
    )

    # Vérifie si le PDF existe
    try:
        if requests.head(url0, timeout=10).status_code == 200:
            return url0
    except Exception:
        pass

    # Deuxième tentative : fallback dossier 1
    try:
        url1 = (
            f"{base_url}1/"
            f"BODACC_{publicationavis}_PDF_Unitaire_{parution}_{numero_annonce_str}.pdf"
        )
        if requests.head(url1, timeout=10).status_code == 200:
            return url1
    except Exception:
        pass

    # Dernier recours : retourner url0 même si pas trouvé
    return url0


@app.route("/bodacc", methods=["GET"])
def bodacc():
    print("➡️ Début /bodacc avec paramètres :", request.args)

    siren = request.args.get("siren")
    departement = request.args.get("departement")

    if not siren:
        return jsonify({"error": "Paramètre 'siren' requis"}), 400

    # Construction URL
    base_url = "https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/"
    params = {
        "dataset": "bodacc-b",
        "rows": 100,
        "sort": "dateparution",
        "q": f"siren:{siren}"
    }

    if departement:
        params["refine.departement"] = departement

    try:
        r = requests.get(base_url, params=params)
        r.raise_for_status()
    except Exception as e:
        print("❌ ERREUR API BODACC :", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erreur lors de l'appel à l'API BODACC"}), 500

    data = r.json()
    records = data.get("records", [])
    results = []

    for rec in records:
        if not isinstance(rec, dict):
            print("❌ Record invalide :", rec)
            continue

        f = rec.get("fields", {})
        if not isinstance(f, dict):
            print("❌ Champ 'fields' invalide :", f)
            continue

        print("📌 TRAITEMENT FIELDS :", f)

        # Sécurisation des champs optionnels
        modifications = f.get("modificationsgenerales", {})
        if not isinstance(modifications, dict):
            modifications = {}

        publicationavis = f.get("publicationavis", {})
        if not isinstance(publicationavis, dict):
            publicationavis = {}

        parution = f.get("parution", {})
        if not isinstance(parution, dict):
            parution = {}

        results.append({
            "date": f.get("dateparution"),
            "numerojo": f.get("numerojo"),
            "numeroannonce": f.get("numeroannonce"),
            "numerodossier": f.get("numerodossier"),
            "tribunal": f.get("tribunal"),
            "description": f.get("description"),
            "parution": {
                "organe": parution.get("organe"),
                "numero": parution.get("numero"),
                "date": parution.get("date")
            },
            "publicationavis": {
                "numerojo": publicationavis.get("numerojo"),
                "numparution": publicationavis.get("numparution"),
                "dateparution": publicationavis.get("dateparution")
            },
            "modifications": modifications
        })

    print("➡️ Résultat final :", results)
    return jsonify(results)



@app.route('/prospection', methods=['GET'])
def prospection():
    try:
        token = get_insee_token()
        if not token:
            flash("Impossible d'obtenir un token INSEE (OAuth).", "error")
            return redirect(url_for("bodacc"))

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
        return redirect(url_for("bodacc"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)