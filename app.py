import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, User

app = Flask(__name__)

# --- CONFIGURATION ---
# IMPORTANT: Use an environment variable for the secret key in production!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-secret-key-change-me')

# Setup Database URI (SQLite used here for mockup, replace with PostgreSQL/MySQL in production)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database with app
db.init_app(app)

# Create tables before first request
with app.app_context():
    db.create_all()

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

# --- ROUTES ---

@app.route('/')
def index():
    # Redirect root to login page by default
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Basic validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))
            
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        # Create new user and hash password securely
        new_user = User(email=email)
        new_user.set_password(password)
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        # Check if user exists and password is correct
        if user and user.check_password(password):
            # Set session variables
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear the entire session
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required  # Protect this route
def dashboard():
    # Only authenticated users can reach this point
    return render_template('dashboard.html', email=session.get('user_email'))

if __name__ == '__main__':
    # Run the Flask development server
    app.run(debug=True)