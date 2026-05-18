import os
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from models import db, User
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)

# --- CONFIGURATION ---
# IMPORTANT: Use an environment variable for the secret key in production!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-secret-key-change-me')

# Setup Database URI
basedir = os.path.abspath(os.path.dirname(__file__))

# Vercel serverless functions have a read-only filesystem except for /tmp
if os.environ.get('VERCEL') == '1':
    fallback_db = 'sqlite:////tmp/app.db'
else:
    fallback_db = 'sqlite:///' + os.path.join(basedir, 'app.db')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or fallback_db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database with app
db.init_app(app)

# Create tables before first request
with app.app_context():
    db.create_all()

# --- SAML HELPER FUNCTIONS ---
def prepare_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(basedir, 'saml'))
    return auth

# --- AUTH DECORATOR ---
def login_required(f):
    """Decorator to require login for specific routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- SAML ROUTES ---

@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    
    if not errors:
        if auth.is_authenticated():
            # Google Workspace NameID is typically the user's email address
            email = auth.get_nameid()
            if not email:
                flash('SAML response did not contain a NameID (email).', 'danger')
                return redirect(url_for('login'))
                
            # Check or create user in DB
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, auth_provider='google_saml')
                db.session.add(user)
                db.session.commit()
            
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully via Google SSO.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('SAML Authentication failed.', 'danger')
            return redirect(url_for('login'))
    else:
        flash(f"Error processing SAML response: {', '.join(errors)}", 'danger')
        return redirect(url_for('login'))

@app.route('/saml/metadata')
def saml_metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    
    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp

# --- STANDARD ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))
            
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(email=email, auth_provider='local')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.auth_provider == 'google_saml':
            flash('This account is linked to Google. Please use Sign in with Google.', 'warning')
        elif user and user.check_password(password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', email=session.get('user_email'))

if __name__ == '__main__':
    app.run(debug=True)