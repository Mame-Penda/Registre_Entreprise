import os
import requests
import secrets
import json
import re
import traceback
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pymysql
import traceback
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

# Initialiser la base de données au démarrage (init_db doit exister)
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
# Si tu veux utiliser un secret déterministe en prod, mets FLASK_SECRET_KEY dans les envs
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
                return render_template("search.html", error="Réponse INSEE inattendue.")
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

    annee = parution[:4] if len(parution) >= 4 else "0000"

    base_url = (
        f"https://www.bodacc.fr/telechargements/COMMERCIALES/PDF/"
        f"{publicationavis}/{annee}/{parution}/"
    )

    url0 = (
        f"{base_url}{numerodossier}/"
        f"BODACC_{publicationavis}_PDF_Unitaire_{parution}_{numero_annonce_str}.pdf"
    )

    try:
        if requests.head(url0, timeout=10).status_code == 200:
            return url0
    except Exception:
        pass

    try:
        url1 = (
            f"{base_url}1/"
            f"BODACC_{publicationavis}_PDF_Unitaire_{parution}_{numero_annonce_str}.pdf"
        )
        if requests.head(url1, timeout=10).status_code == 200:
            return url1
    except Exception:
        pass

    return url0


@app.route("/bodacc", methods=["GET"])
def bodacc():
    try:
        print("=" * 80)
        print("🔍 DÉBUT BODACC")
        print(f"Session user: {session.get('user')}")
        print(f"Request args: {request.args}")
        
        if "user" not in session:
            print("❌ User not in session")
            if request.accept_mimetypes.accept_json:
                return jsonify({"error": "Non authentifié"}), 401
            return redirect(url_for("login"))

        s = (request.args.get("siret") or request.args.get("siren") or "").strip()
        print(f"📝 Paramètre reçu: '{s}'")
        
        if not s:
            print("❌ Paramètre vide")
            if request.accept_mimetypes.accept_json:
                return jsonify({"error": "Paramètre 'siret' ou 'siren' manquant."}), 400
            return jsonify({"error": "Paramètre manquant"}), 400

        # Validation
        if s.isdigit() and len(s) == 14:
            siren = s[:9]
            print(f"✅ SIRET 14 chiffres → SIREN: {siren}")
        elif s.isdigit() and len(s) == 9:
            siren = s
            print(f"✅ SIREN 9 chiffres: {siren}")
        else:
            error_msg = f"Numéro invalide: {len(s)} chiffres"
            print(f"❌ {error_msg}")
            return jsonify({"error": error_msg}), 400

        url = f"https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/?dataset=annonces-commerciales&q={siren}&rows=50"
        print(f"🌐 URL API: {url}")
        
        results = []
        
        print("📡 Appel API BODACC...")
        r = requests.get(url, timeout=20)
        print(f"📊 Status Code: {r.status_code}")
        
        r.raise_for_status()
        data = r.json()
        records = data.get("records", [])
        print(f"📦 Nombre de records: {len(records)}")
        
        for rec in records:
            f = rec.get("fields", {})
            
            # Traiter la description
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
        
        print(f"✅ {len(results)} résultats construits")
        print("=" * 80)
        
        return jsonify({"results": results})
        
    except Exception as e:
        print("=" * 80)
        print(f"❌❌❌ ERREUR CRITIQUE ❌❌❌")
        print(f"Type: {type(e).__name__}")
        print(f"Message: {str(e)}")
        print("Traceback complet:")
        traceback.print_exc()
        print("=" * 80)
        return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total FROM favoris WHERE user_id = %s", (session['user_id'],))
    nb_favoris = cursor.fetchone()['total']

    cursor.execute("""
                   SELECT * FROM favoris
                   WHERE user_id = %s
                   ORDER BY added_at DESC
                   LIMIT 5
                   """, (session['user_id'],))
    derniers_favoris = cursor.fetchall()

    con.close()
    cursor.close()

    return render_template('dashboard.html', nb_favoris=nb_favoris, derniers_favoris=derniers_favoris)

@app.route('/favoris/add/<siren>', methods=['POST'])
def add_favori(siren):
    """Ajouter une entreprise aux favoris"""
    
    # Vérifier si l'utilisateur est connecté
    if 'user_id' not in session:
        return jsonify({'error': 'Non connecté'}), 401

    user_id = session['user_id']

    # Récupérer les infos de l'entreprise
    entreprise = get_entreprise_by_siren(siren)
    if not entreprise:
        return jsonify({'error': 'Entreprise introuvable'}), 404

    conn = get_db_connection()
    cursor = conn.cursor()

    # Vérifier si le favori existe déjà
    cursor.execute("""
        SELECT 1 FROM favoris 
        WHERE user_id = %s AND siren = %s
    """, (user_id, siren))

    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Déjà dans les favoris'}), 409

    # Insérer dans favoris
    cursor.execute("""
        INSERT INTO favoris (user_id, siren, nom_entreprise)
        VALUES (%s, %s, %s)
    """, (user_id, siren, entreprise['nom']))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'success': True, 'message': 'Ajouté aux favoris'})


@app.route('/favoris/remove/<siren>', methods=['POST'])
def remove_favori(siren):
    """Retirer une entreprise des favoris"""

    # Vérifier si connecté
    if 'user_id' not in session:
        return jsonify({'error': 'Non connecté'}), 401

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Supprimer le favori, retourner un élément si quelque chose a été supprimé
    cursor.execute("""
        DELETE FROM favoris
        WHERE user_id = %s AND siren = %s
        RETURNING id
    """, (user_id, siren))

    deleted = cursor.fetchone()

    conn.commit()
    cursor.close()
    conn.close()

    if not deleted:
        return jsonify({'error': 'Favori introuvable'}), 404

    return jsonify({'success': True, 'message': 'Retiré des favoris'})



@app.route('/favoris')
def mes_favoris():
    """Afficher les favoris de l'utilisateur"""

    # Vérifier si connecté
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, siren, nom_entreprise, created_at
        FROM favoris
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user_id,))

    # Récupérer les favoris
    rows = cursor.fetchall()

    # Transformer en dictionnaires (PostgreSQL ne renvoie pas du dict)
    favoris = []
    for r in rows:
        favoris.append({
            "id": r[0],
            "siren": r[1],
            "nom_entreprise": r[2],
            "created_at": r[3]
        })

    cursor.close()
    conn.close()

    return render_template("favoris.html", favoris=favoris)


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
