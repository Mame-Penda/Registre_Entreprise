# app.py
import os
import requests
import secrets
import json
import re
import traceback
from urllib.parse import urlparse, quote_plus, unquote_plus

from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, jsonify, abort
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv

# Logging
import logging, sys
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# DB drivers
import pymysql
pymysql.install_as_MySQLdb()
load_dotenv()

DATABASE_URL = os.environ.get('DATABASE_URL')

# init_db must be present in your repo and create required tables for Postgres/SQLite
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
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(16)

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
        logging.debug("INSEE OAuth: CLIENT_ID/CLIENT_SECRET manquants")
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
        logging.exception("INSEE OAuth: erreur réseau")
        return None

    if not resp.ok:
        logging.error("INSEE OAuth HTTP %s: %s", resp.status_code, resp.text[:200])
        return None

    try:
        payload = resp.json()
    except ValueError:
        logging.error("INSEE OAuth: réponse non-JSON")
        return None

    return payload.get("access_token")


def generate_pdf_url(annonce):
    """
    Génère une URL PDF BODACC sans vérification (pour éviter les timeouts).
    Retourne l'URL la plus probable sans faire de requête HEAD.
    """
    try:
        publicationavis = annonce.get("publicationavis") or "A"
        parution = annonce.get("parution") or ""
        numerodossier = str(annonce.get("numerodossier") or "1")
        numero_annonce = annonce.get("numeroannonce")
        
        if numero_annonce is None or not str(numero_annonce).isdigit():
            numero_annonce_str = "00000"
        else:
            numero_annonce_str = str(numero_annonce).zfill(5)
        
        annee = parution[:4] if len(parution) >= 4 else "0000"
        base_url = (
            f"https://www.bodacc.fr/telechargements/COMMERCIALES/PDF/"
            f"{publicationavis}/{annee}/{parution}/"
        )
        
        # Retourne l'URL la plus probable (avec dossier 1 par défaut)
        # Sans vérification HEAD pour éviter les timeouts
        url = f"{base_url}1/BODACC_{publicationavis}_PDF_Unitaire_{parution}_{numero_annonce_str}.pdf"
        return url
    except Exception as e:
        logging.debug(f"Erreur génération URL PDF: {e}")
        return None


# -------------------------
# Routes basiques (login/register/...)
# -------------------------
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
            # Sauvegarde email + user_id si possible (table users doit fournir id)
            session["user"] = email
            try:
                # tenter de récupérer user_id
                conn = get_db_connection()
                cur = conn.cursor()
                if DATABASE_URL:
                    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                else:
                    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
                u = cur.fetchone()
                if u:
                    session['user_id'] = u[0]
                cur.close()
                conn.close()
            except Exception:
                pass
            return redirect(url_for("search_company"))
        else:
            return render_template("login.html", error="Identifiants incorrects.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("user_id", None)
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")
        if not name or not re.match(r"^[a-zA-ZÀ-ÿ\s]+$", name):
            flash("Le nom doit contenir uniquement des lettres et des espaces.", "error")
            return render_template("register.html")
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
        # set user_id if DB returns it later
        return redirect(url_for("search_company"))
    return render_template("register.html")


# -------------------------
# Search company (index)
# -------------------------
@app.route("/", methods=["GET", "POST"])
def search_company():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("search.html")

    # POST
    siret = request.form.get("siret", "").strip()
    if not siret.isdigit() or len(siret) != 14:
        return render_template("search.html", error="Numéro SIRET invalide. Il doit contenir 14 chiffres.")

    if not INSEE_API_KEY:
        return render_template("search.html", error="INSEE_API_KEY manquant. Ajoutez-le dans votre .env puis redémarrez l'app.")

    url = API_SIRENE_SIRET_URL.format(siret=siret)
    try:
        resp = requests.get(url, headers=insee_headers(), timeout=15)
    except requests.RequestException as e:
        return render_template("search.html", error=f"Erreur de connexion à l'API INSEE : {e}")

    if resp.status_code != 200:
        return render_template("search.html", error="Entreprise introuvable dans l'API INSEE.")

    payload = resp.json()
    data = payload.get("etablissement") or payload.get("uniteLegale")
    if not data:
        return render_template("search.html", error="Réponse INSEE inattendue.")

    # save history (best-effort)
    try:
        nom_entreprise = (data.get("uniteLegale") or {}).get("denominationUniteLegale") or data.get("denominationUniteLegale") or "Entreprise"
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
    except Exception:
        logging.exception("Erreur enregistrement historique")

    has_articles = 'articles' in app.view_functions
    return render_template("results.html", data=data, has_articles=has_articles)


# -------------------------
# BODACC route (JSON) : retourne "results": [ ... ] pour ton front
# -------------------------
ALLOWED_PDF_HOSTS = {
    "www.bodacc.fr",
    "bodacc-datadila.opendatasoft.com",
    "bodacc.fr",
    "datadila.opendatasoft.com",
    "opendatasoft.com"
}

def is_allowed_pdf(url: str) -> bool:
    try:
        p = urlparse(url)
        host = p.netloc.lower()
        # autorise sous-domaines d'opendatasoft/bodacc
        for allow in ALLOWED_PDF_HOSTS:
            if host.endswith(allow):
                return True
        return False
    except Exception:
        return False

@app.route("/bodacc", methods=["GET"])
def bodacc():
    """
    Appelé par le front (fetch). Param: siret OR siren.
    Renvoie JSON: {"results": [ {date_parution, type_avis, tribunal, reference, description, pdf_url}, ... ]}
    """
    if "user" not in session:
        if request.accept_mimetypes.accept_json:
            return jsonify({"error": "Non authentifié"}), 401
        return redirect(url_for("login"))

    s = (request.args.get("siret") or request.args.get("siren") or "").strip()
    if not s:
        return jsonify({"error": "Paramètre 'siret' ou 'siren' manquant."}), 400

    if s.isdigit() and len(s) == 14:
        siren = s[:9]
    elif s.isdigit() and len(s) == 9:
        siren = s
    else:
        return jsonify({"error": "Numéro SIREN/SIRET invalide."}), 400

    url = f"https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/?dataset=annonces-commerciales&q={siren}&rows=50&sort=dateparution"
    
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
    except requests.RequestException as e:
        logging.exception("Erreur récupération annonces BODACC")
        return jsonify({"error": f"Erreur récupération annonces BODACC : {str(e)}"}), 502

    try:
        payload = r.json()
    except ValueError as e:
        logging.error("Erreur parsing JSON BODACC")
        return jsonify({"error": "Réponse invalide de l'API BODACC"}), 502

    records = payload.get("records", [])
    results = []

    for rec in records:
        try:
            f = rec.get("fields", {}) or {}
            
            # Description robuste
            desc = f.get("modificationsgenerales") or f.get("description") or ""
            if isinstance(desc, str) and desc.strip():
                try:
                    j = json.loads(desc)
                    if isinstance(j, dict):
                        desc = " | ".join(f"{k}: {v}" for k, v in j.items())
                except Exception:
                    pass
            elif isinstance(desc, dict):
                desc = " | ".join(f"{k}: {v}" for k, v in desc.items())
            else:
                desc = str(desc) if desc else ""

            # Essayer plusieurs champs pour l'URL PDF
            pdf_url = (
                f.get("urlpdf") or
                f.get("lienAnnonce") or
                f.get("url") or
                f.get("url_publication") or
                f.get("fichierPdf") or
                f.get("pdf") or
                None
            )
            
            # Si pas de PDF fourni, générer l'URL (sans vérification)
            if not pdf_url:
                try:
                    pdf_url = generate_pdf_url(f)
                except Exception as e:
                    logging.debug(f"Erreur génération PDF: {e}")
                    pdf_url = None

            # Vérifier que l'URL est autorisée
            if pdf_url and not is_allowed_pdf(pdf_url):
                logging.warning("pdf_url host not allowed: %s", pdf_url)
                pdf_url = None

            results.append({
                "date_parution": f.get("dateparution") or f.get("date") or "",
                "type_avis": f.get("typeavis_lib") or f.get("familleavis_lib") or f.get("typeavis") or "",
                "tribunal": f.get("tribunal") or f.get("source") or "",
                "reference": str(f.get("numeroannonce") or ""),
                "description": desc,
                "pdf_url": pdf_url
            })
        except Exception as e:
            logging.warning(f"Erreur traitement d'un enregistrement BODACC: {e}")
            continue

    return jsonify({"results": results})


# -------------------------
# Page qui embed un PDF (sécurisé)
# -------------------------
@app.route("/bodacc/view_pdf")
def bodacc_view_pdf():
    """
    Affiche un PDF dans un iframe. Paramètre `url` encodée (urlencoded).
    Pour des raisons de sécurité, on n'autorise que certains hosts (bodacc/opendatasoft).
    Usage: /bodacc/view_pdf?url=<urlencoded_pdf_url>
    """
    url = request.args.get("url")
    if not url:
        return "Paramètre 'url' manquant", 400
    # url peut être encodée par le front
    url = unquote_plus(url)
    if not is_allowed_pdf(url):
        abort(403, description="URL PDF non autorisée")
    # On peut aussi faire une HEAD pour vérifier content-type = application/pdf (optionnel)
    try:
        head = requests.head(url, timeout=6)
        content_type = head.headers.get("Content-Type", "")
        if "pdf" not in content_type.lower():
            # laisser quand même (certaines sources n'ont pas bon header) — on logge
            logging.warning("Le content-type du PDF attendu n'est pas 'pdf' pour %s (got %s)", url, content_type)
    except Exception:
        logging.debug("Impossible d'effectuer HEAD sur le PDF (on continue)")

    return render_template("bodacc_pdf_view.html", pdf_url=url)


# -------------------------
# Favoris / dashboard / etc.
# -------------------------
@app.route('/favoris/add/<siren>', methods=['POST'])
def add_favori(siren):
    if 'user_id' not in session:
        return jsonify({'error': 'Non connecté'}), 401
    user_id = session['user_id']

    # get_entreprise_by_siren must exist in your codebase. fallback: store minimal info
    entreprise = {"nom": request.json.get("nom") if request.is_json else request.form.get("nom")} if request else None
    # If you have a function get_entreprise_by_siren, use it:
    try:
        from helpers import get_entreprise_by_siren  # optionally
        entreprise = get_entreprise_by_siren(siren)
    except Exception:
        pass

    if not entreprise:
        entreprise = {"nom": "Entreprise inconnue"}

    conn = get_db_connection()
    cursor = conn.cursor()
    # adapt query for sqlite vs postgres (psycopg2 returns tuple)
    if DATABASE_URL:
        cursor.execute("SELECT 1 FROM favoris WHERE user_id = %s AND siren = %s", (user_id, siren))
    else:
        cursor.execute("SELECT 1 FROM favoris WHERE user_id = ? AND siren = ?", (user_id, siren))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Déjà dans les favoris'}), 409

    if DATABASE_URL:
        cursor.execute("INSERT INTO favoris (user_id, siren, nom_entreprise) VALUES (%s, %s, %s)", (user_id, siren, entreprise.get("nom")))
    else:
        cursor.execute("INSERT INTO favoris (user_id, siren, nom_entreprise) VALUES (?, ?, ?)", (user_id, siren, entreprise.get("nom")))

    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True, 'message': 'Ajouté aux favoris'})


@app.route('/favoris/remove/<siren>', methods=['POST', 'DELETE'])
def remove_favori(siren):
    if 'user_id' not in session:
        return jsonify({'error': 'Non connecté'}), 401
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    if DATABASE_URL:
        # returning id works on postgres
        cursor.execute("DELETE FROM favoris WHERE user_id = %s AND siren = %s RETURNING id", (user_id, siren))
        deleted = cursor.fetchone()
    else:
        cursor.execute("DELETE FROM favoris WHERE user_id = ? AND siren = ?", (user_id, siren))
        deleted = True  # sqlite doesn't return
    conn.commit()
    cursor.close()
    conn.close()
    if DATABASE_URL and not deleted:
        return jsonify({'error': 'Favori introuvable'}), 404
    return jsonify({'success': True, 'message': 'Retiré des favoris'})


@app.route('/mes_favoris')
def mes_favoris():
    """Page affichant les favoris de l'utilisateur"""
    logging.debug(" DEBUG: entrée dans /mes_favoris")
    
    if 'user_id' not in session:
        logging.debug(" Utilisateur non connecté, redirection vers login")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_URL:
            cursor.execute(
                "SELECT id, siren, nom_entreprise, created_at FROM favoris WHERE user_id = %s ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cursor.fetchall()
            favoris = []
            for r in rows:
                favoris.append({
                    "id": r[0],
                    "siren": r[1],
                    "nom_entreprise": r[2],
                    "date_ajout": r[3]
                })
        else:
            cursor.execute(
                "SELECT id, siren, nom_entreprise, created_at FROM favoris WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cursor.fetchall()
            favoris = []
            for r in rows:
                favoris.append({
                    "id": r[0],
                    "siren": r[1],
                    "nom_entreprise": r[2],
                    "date_ajout": r[3]
                })
        
        cursor.close()
        conn.close()
        
        logging.debug(f" {len(favoris)} favoris trouvés pour user_id={user_id}")
        return render_template("favoris.html", favoris=favoris)
        
    except Exception as e:
        logging.exception(" ERREUR dans /mes_favoris")
        flash("Erreur lors du chargement des favoris", "error")
        return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Dashboard avec statistiques réelles"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session.get('user')
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Nombre de favoris
        if DATABASE_URL:
            cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_id = ?", (user_id,))
        nb_favoris = cursor.fetchone()[0]
        
        # Nombre total de recherches
        if DATABASE_URL:
            cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = %s", (user_email,))
        else:
            cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = ?", (user_email,))
        total_recherches = cursor.fetchone()[0]
        
        # Recherches de la semaine (7 derniers jours)
        if DATABASE_URL:
            cursor.execute("""
                SELECT COUNT(*) FROM historique 
                WHERE user_email = %s 
                AND date_recherche >= NOW() - INTERVAL '7 days'
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM historique 
                WHERE user_email = ? 
                AND date_recherche >= datetime('now', '-7 days')
            """, (user_email,))
        recherches_semaine = cursor.fetchone()[0]
        
        # Recherches d'aujourd'hui
        if DATABASE_URL:
            cursor.execute("""
                SELECT COUNT(*) FROM historique 
                WHERE user_email = %s 
                AND DATE(date_recherche) = CURRENT_DATE
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM historique 
                WHERE user_email = ? 
                AND DATE(date_recherche) = DATE('now')
            """, (user_email,))
        recherches_jour = cursor.fetchone()[0]
        
        # Recherches par jour (7 derniers jours)
        if DATABASE_URL:
            cursor.execute("""
                SELECT DATE(date_recherche) as jour, COUNT(*) as nb
                FROM historique
                WHERE user_email = %s
                AND date_recherche >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(date_recherche)
                ORDER BY jour DESC
                LIMIT 7
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT DATE(date_recherche) as jour, COUNT(*) as nb
                FROM historique
                WHERE user_email = ?
                AND date_recherche >= datetime('now', '-7 days')
                GROUP BY DATE(date_recherche)
                ORDER BY jour DESC
                LIMIT 7
            """, (user_email,))
        
        recherches_data = cursor.fetchall()
        
        # Préparer les données pour le graphique (7 derniers jours)
        from datetime import datetime, timedelta
        jours_labels = []
        jours_data = []
        for i in range(6, -1, -1):
            jour = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            jours_labels.append(['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'][(datetime.now() - timedelta(days=i)).weekday()])
            
            # Trouver le nombre de recherches pour ce jour
            count = 0
            for r in recherches_data:
                if str(r[0]) == jour:
                    count = r[1]
                    break
            jours_data.append(count)
        
        recherches_par_jour = {
            'labels': jours_labels,
            'data': jours_data
        }
        
        # 5 dernières recherches
        if DATABASE_URL:
            cursor.execute("""
                SELECT siret, nom_entreprise, date_recherche 
                FROM historique 
                WHERE user_email = %s 
                ORDER BY date_recherche DESC 
                LIMIT 5
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT siret, nom_entreprise, date_recherche 
                FROM historique 
                WHERE user_email = ? 
                ORDER BY date_recherche DESC 
                LIMIT 5
            """, (user_email,))
        dernieres_recherches = cursor.fetchall()
        
        stats = {
            'nb_favoris': nb_favoris,
            'total_recherches': total_recherches,
            'recherches_semaine': recherches_semaine,
            'recherches_jour': recherches_jour
        }
        
        return render_template(
            'dashboard.html',
            stats=stats,
            dernieres_recherches=dernieres_recherches,
            recherches_par_jour=recherches_par_jour
        )
        
    except Exception as e:
        logging.exception("Erreur dashboard")
        return render_template(
            'dashboard.html', 
            stats={
                'nb_favoris': 0,
                'total_recherches': 0,
                'recherches_semaine': 0,
                'recherches_jour': 0
            }, 
            dernieres_recherches=[], 
            recherches_par_jour={'labels': [], 'data': []}
        )
    finally:
        cursor.close()
        conn.close()

@app.route('/historique')
def historique():
    """Page d'historique des recherches"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session.get('user')
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Nombre de recherches
        if DATABASE_URL:
            cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = %s", (user_email,))
        else:
            cursor.execute("SELECT COUNT(*) FROM historique WHERE user_email = ?", (user_email,))
        nb_recherches = cursor.fetchone()[0]
        
        # Nombre de favoris
        if DATABASE_URL:
            cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM favoris WHERE user_id = ?", (user_id,))
        nb_favoris = cursor.fetchone()[0]
        
        # Toutes les recherches
        if DATABASE_URL:
            cursor.execute("""
                SELECT siret, nom_entreprise, date_recherche 
                FROM historique 
                WHERE user_email = %s 
                ORDER BY date_recherche DESC 
                LIMIT 50
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT siret, nom_entreprise, date_recherche 
                FROM historique 
                WHERE user_email = ? 
                ORDER BY date_recherche DESC 
                LIMIT 50
            """, (user_email,))
        dernieres_recherches = cursor.fetchall()
        
        stats = {
            'nb_recherches': nb_recherches,
            'nb_favoris': nb_favoris
        }
        
        return render_template('historique.html', stats=stats, dernieres_recherches=dernieres_recherches)
        
    except Exception as e:
        logging.exception("Erreur historique")
        return render_template('historique.html', stats={'nb_recherches': 0, 'nb_favoris': 0}, dernieres_recherches=[])
    finally:
        cursor.close()
        conn.close()


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


# -------------------------
# Routes supplémentaires (Articles, À propos, Mot de passe oublié)
# -------------------------

@app.route('/articles')
def articles():
    """Page affichant les articles et actualités"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('articles.html')


@app.route('/about')
def about():
    """Page À propos"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('about.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Page de réinitialisation de mot de passe"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Veuillez entrer votre adresse email.", "error")
            return render_template('forgot_password.html')
        
        # Vérifier si l'utilisateur existe
        conn = get_db_connection()
        cursor = conn.cursor()
        if DATABASE_URL:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # TODO: Implémenter l'envoi d'email avec token de réinitialisation
            flash("Un email de réinitialisation a été envoyé (fonctionnalité en développement).", "info")
        else:
            # Ne pas révéler si l'email existe ou non (sécurité)
            flash("Si cet email existe, un lien de réinitialisation a été envoyé.", "info")
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# -------------------------
# Routes pour les Notes
# -------------------------

@app.route('/notes', methods=['GET', 'POST'])
def notes_page():
    """Page de gestion des notes personnelles"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Ajouter une nouvelle note (POST)
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if content:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                if DATABASE_URL:
                    cursor.execute(
                        "INSERT INTO notes (user_id, content) VALUES (%s, %s)",
                        (user_id, content)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO notes (user_id, content) VALUES (?, ?)",
                        (user_id, content)
                    )
                conn.commit()
                flash("Note ajoutée avec succès !", "success")
            except Exception as e:
                logging.error(f"Erreur ajout note: {e}")
                flash("Erreur lors de l'ajout de la note.", "error")
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('notes_page'))
    
    # Récupérer toutes les notes de l'utilisateur (GET)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if DATABASE_URL:
            cursor.execute(
                "SELECT id, content, created_at FROM notes WHERE user_id = %s ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cursor.fetchall()
            notes = [{"id": r[0], "content": r[1], "created_at": r[2]} for r in rows]
        else:
            cursor.execute(
                "SELECT id, content, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cursor.fetchall()
            notes = [{"id": r[0], "content": r[1], "created_at": r[2]} for r in rows]
    except Exception as e:
        logging.error(f"Erreur récupération notes: {e}")
        notes = []
    finally:
        cursor.close()
        conn.close()
    
    return render_template('notes.html', notes=notes)


@app.route('/notes/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    """Supprimer une note"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Vérifier que la note appartient bien à l'utilisateur
        if DATABASE_URL:
            cursor.execute(
                "DELETE FROM notes WHERE id = %s AND user_id = %s RETURNING id",
                (note_id, user_id)
            )
            deleted = cursor.fetchone()
        else:
            cursor.execute(
                "DELETE FROM notes WHERE id = ? AND user_id = ?",
                (note_id, user_id)
            )
            deleted = cursor.rowcount > 0
        
        conn.commit()
        
        if deleted:
            flash("Note supprimée avec succès !", "success")
        else:
            flash("Note introuvable ou non autorisée.", "error")
    except Exception as e:
        logging.error(f"Erreur suppression note: {e}")
        flash("Erreur lors de la suppression.", "error")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('notes_page'))


# -------------------------
# Démarrage de l'application
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)