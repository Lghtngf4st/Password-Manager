import os
import re
import secrets
import string

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from models import db, User, VaultItem
from helpers import login_required, derive_vault_key, encrypt_text, decrypt_text

def create_app():
    app = Flask(__name__)
    
    # Core Flask configuration
    app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
    
    # Session configuration
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = os.path.join(app.instance_path, "flask_session")
    app.config["SESSION_USE_SIGNER"] = True
    
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    
    # Set SESSION_COOKIE_SECURE to False in local dev; True when deploying behind HTTPS
    app.config["SESSION_COOKIE_SECURE"] = False
    
    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    
    # SQLAlchemy configuration
    db_path = os.path.join(app.instance_path, "vault.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Initialize extensions
    Session(app)
    db.init_app(app)
    
    # Create tables (first run)
    with app.app_context():
        db.create_all()
        
    return app

app = create_app()
    
    
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect("/vault")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    
    # Only remove auth keys so flash messages still appear
    session.pop("user_id", None)
    session.pop("vault_key", None)
    
    # User reached route via Post
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        
        # Ensure username was submitted
        if not username:
            flash("Must provide username")
            return redirect("/login")
        
        # Ensure password is submitted
        if not password:
            flash("Must provide password")
            return redirect("/login")
        
        # Query database for username
        user = User.query.filter_by(username=username).first()
        
        # Check username exists AND password matches
        if user is None or not check_password_hash(user.password_hash, password):
            flash("Incorrect username and/or password. Please try again")
            return redirect("/login")
        
        # Initialize user session
        session["user_id"] = user.id
        vault_key = derive_vault_key(password, user.kdf_salt)
        session["vault_key"] = vault_key
        
        return redirect("/vault")

    return render_template("login.html")    

@app.route("/logout", methods=["POST"])
def logout():
    """Log user out"""
    
    # Forget any user_id
    session.clear()
    
    # Redirect user to login form
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register User"""
    # Forget any user id
    session.clear()

    # User reached route via POST
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirmation = request.form.get("confirmation") or ""
        
        # Ensure username is submitted
        if not username:
            flash("Must provide username")
            return redirect("/register")

        # Ensure password is submitted
        if not password:
            flash("Must provide password")
            return redirect("/register")

        # Ensure password confirmation was submitted
        if not confirmation:
            flash("Must confirm password")
            return redirect("/register")

        # Ensure password and confirmation match
        if password != confirmation:
            flash("Passwords do not match")
            return redirect("/register")

        # Query database for username
        existing = User.query.filter_by(username=username).first()
        if existing is not None:
            flash("Username already exists")
            return redirect("/register")

        # Create new user with hashed password + per-user KDF salt
        password_hash = generate_password_hash(password)
        kdf_salt = secrets.token_bytes(16)
        
        user = User(username=username, password_hash=password_hash, kdf_salt=kdf_salt)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Username already exists")
            return redirect("/register")
        
        # Remember which user is logged in
        session["user_id"] = user.id

        # Redirect user to home page
        return redirect("/login")

    return render_template("register.html")


@app.route("/vault")
@login_required
def vault():
    """Show vault items"""
    user_id = session["user_id"]
    
    q = (request.args.get("q") or "").strip()
    
    # Base query: only items belonging to the current user
    query = VaultItem.query.filter(VaultItem.user_id == user_id)
    
    # if a search query is provided, narrow results
    if q:
        # Case-insensitive contains match on label and url
        like = f"%{q}%"
        query = query.filter(
            or_(
                VaultItem.label.ilike(like),
                VaultItem.url.ilike(like)
            )
        )
    
    # Sort results for consisten display
    items = query.order_by(VaultItem.label.asc()).all()
    
    return render_template("vault.html", items=items, q=q)
 

@app.route("/vault/<int:item_id>")
@login_required
def vault_item(item_id):
    """Show a single vault item"""
    user_id = session["user_id"]
    
    vault_key = session.get("vault_key")
    if vault_key is None:
        flash("Session expired. Please log in again")
        return redirect("/login")
    
    item = VaultItem.query.filter_by(id=item_id, user_id=user_id).first()
    # If item can't be retrieved
    if item is None:
        abort(404)
    
    # Decrypt for display
    username = decrypt_text(item.login_username_encrypted, vault_key) if item.login_username_encrypted else ""
    password = decrypt_text(item.login_password_encrypted, vault_key) if item.login_password_encrypted else ""
    notes = decrypt_text(item.notes_encrypted, vault_key) if item.notes_encrypted else ""
    
    return render_template("vault_item.html", item=item, username=username, password=password, notes=notes)


@app.route("/vault/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def vault_edit(item_id):
    user_id = session["user_id"]
    
    vault_key = session.get("vault_key")
    if vault_key is None:
        flash("Session expired. Please log in again.")
        return redirect("/login")
    
    item = VaultItem.query.filter_by(id=item_id, user_id=user_id).first()
    if item is None:
        abort(404)
        
    if request.method == "POST":
        label = (request.form.get("label") or "").strip()
        url = (request.form.get("url") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")
        notes = (request.form.get("notes") or "").strip()
        
        if not label:
            flash("Must provide a website or label")
            return redirect(f"/vault/{item_id}/edit")
        
        if not password:
            flash("Must provide a password")
            return redirect(f"/vault/{item_id}/edit")
        
        item.label = label
        item.url = url if url else None
        item.login_username_encrypted = encrypt_text(username, vault_key) if username else None
        item.login_password_encrypted = encrypt_text(password, vault_key)
        item.notes_encrypted = encrypt_text(notes, vault_key) if notes else None
        
        db.session.commit()
        flash("Vault item updated")
        return redirect(f"/vault/{item_id}")
    
    # GET: decrypt current values for the form
    current_username = decrypt_text(item.login_username_encrypted, vault_key) if item.login_username_encrypted else ""
    current_password = decrypt_text(item.login_password_encrypted, vault_key) if item.login_password_encrypted else ""
    current_notes = decrypt_text(item.notes_encrypted, vault_key) if item.notes_encrypted else ""
    
    return render_template("vault_edit.html", item=item, username=current_username, password=current_password, notes=current_notes)


@app.route("/vault/<int:item_id>/delete", methods=["POST"])
@login_required
def vault_delete(item_id):
    user_id = session["user_id"]
    
    item = VaultItem.query.filter_by(id=item_id, user_id=user_id).first()
    if item is None:
        abort(404)
    
    db.session.delete(item)
    db.session.commit()
    
    flash("Vault item deleted")
    return redirect("/vault")

    
@app.route("/vault/new", methods=["GET", "POST"])
@login_required
def vault_new():
    """Create a new vault item"""
    user_id = session["user_id"]
    
    vault_key = session.get("vault_key")
    if vault_key is None:
        flash("Session expired. Please log in again")
        return redirect("/login")
    
    if request.method == "POST":
        label = (request.form.get("label") or "").strip()
        url = (request.form.get("url") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")
        notes = (request.form.get("notes") or "").strip()
        
        # Basic validation
        if not label:
            flash("Must provide a website or label")
            return redirect("/vault/new")
        
        if not password:
            flash("Must provide a password")
            return redirect("/vault/new")
        
        # Store sensitive fields as bytes so the schema does not change later
        item = VaultItem(
            user_id=user_id,
            label=label,
            url=url if url else None,
            login_username_encrypted=encrypt_text(username, vault_key) if username else None,
            login_password_encrypted=encrypt_text(password, vault_key),
            notes_encrypted=encrypt_text(notes, vault_key) if notes else None,
        )

        db.session.add(item)
        db.session.commit()
        
        flash("Vault item added")
        return redirect("/vault")
    
    return render_template("vault_new.html")


@app.route("/password_strength", methods=["GET", "POST"])
def password_strength():
    """Provide assessment on password strength"""
    if request.method == "POST":
        pw = (request.form.get("password") or "").strip()
        
        # Basic metrics
        length = len(pw)
        has_lower = bool(re.search(r"[a-z]", pw))
        has_upper = bool(re.search(r"[A-Z]", pw))
        has_digit = bool(re.search(r"\d", pw))
        has_symbol = bool(re.search(r"[^A-Za-z0-9]", pw))
        
        # Very common passwords / patterns
        common = {"password", "123456", "12345678", "qwerty", "admin"}
        lowered = pw.lower()
        
        score = 0
        feedback = []
        
        if not pw:
            return jsonify({"score": 0, "label": "Empty", "feedback": ["Enter a password."]})
        
        if lowered in common:
            return jsonify({"score": 0, "label": "Very weak", "feedback": ["This is a very common password."]})

        # Length scoring
        if length >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters.")
            
        if length >= 12:
            score += 1
        else:
            feedback.append("12+ characters is much stronger.")
        
        # Variety scoring
        variety = sum([has_lower, has_upper, has_digit, has_symbol])
        
        if variety == 1:
            feedback.append("Using only one character type is risky.")
        
        if variety >= 2:
            score += 1
        else:
            feedback.append("Add a mix of letters, numbers, or symbols.")

        if variety >= 3:
            score += 1
            
        # Clamp to 0-4
        score = max(0, min(4, score))
        
        labels = ["Very weak", "Weak", "Okay", "Strong", "Very strong"]
        label = labels[score]
        
        # Extra feedback
        if not has_upper:
            feedback.append("Consider adding uppercase letters.")
        if not has_digit:
            feedback.append("Consider adding numbers.")
        if not has_symbol:
            feedback.append("Consider adding symbols.")
            
        # De-duplicate feedback while preserving order
        seen = set()
        feedback = [f for f in feedback if not(f in seen or seen.add(f))]
        
        return jsonify(
            {
                "score": score,
                "label": label,
                "length": length,
                "has_lower": has_lower,
                "has_upper": has_upper,
                "has_digit": has_digit,
                "has_symbol": has_symbol,
                "feedback": feedback[:4],
            }
        )
    
    else:
        return render_template("password_strength.html")
        
    
@app.route("/password_generator", methods=["GET", "POST"])
@login_required
def password_generator():
    """Generate random password"""
    if request.method == "POST":
        # Read options (safe defaults)
        try:
            length = int(request.form.get("length", 16))
        except ValueError:
            length = 16
            
        include_upper = (request.form.get("upper", "1") == "1")
        include_lower = (request.form.get("lower", "1") == "1")
        include_digits = (request.form.get("digits", "1") == "1")
        include_symbols = (request.form.get("symbols", "1") == "1")
        
        # Clamp length to a reasonable range
        length = max(8, min(64, length))
        
        # Build allowed character pool
        pool = ""
        required_sets = []
        
        if include_lower:
            pool += string.ascii_lowercase
            required_sets.append(string.ascii_lowercase)
        if include_upper:
            pool += string.ascii_uppercase
            required_sets.append(string.ascii_uppercase)
        if include_digits:
            pool += string.digits
            required_sets.append(string.digits)
        if include_symbols:
            symbols = "!@#$%^&*)-_=+[]{};:,.?/"
            pool += symbols
            required_sets.append(symbols)
            
        if not pool:
            return jsonify({"error": "Select at least one character set."}), 400
        
        # Ensure the password contains at least one char from each selected set
        password_chars = [secrets.choice(charset) for charset in required_sets]
        
        # Fill the rest from the full pool
        password_chars += [secrets.choice(pool) for _ in range(length - len(password_chars))]
        
        # Shuffle so required characters aren't in predictable positions
        secrets.SystemRandom().shuffle(password_chars)
        
        password = "".join(password_chars)
        return jsonify({"password": password, "length": length})
      
    return render_template("password_generator.html")


if __name__ == "__main__":
    app.run(debug=True)
    
    
    