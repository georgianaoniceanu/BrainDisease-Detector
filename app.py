from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key'  # REQUIRED for Flask-Login

CORS(app)

DATABASE = 'cognitive_results.db'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # redirect to login page if user is not logged in

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Database Initialization
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Create results table with user_id foreign key
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                quiz_score INTEGER,
                visual_level INTEGER,
                reaction_time INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Eroare la crearea bazei de date: {e}")
    finally:
        if conn:
            conn.close()

# Run this function once at startup
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data[1], password):
            user = User(user_data[0], username)
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:
            # Hash the password before saving
            hashed_password = generate_password_hash(password, method='scrypt')
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- Existing Endpoints ---

@app.route('/api/analyze_all', methods=['POST'])
@login_required
def analyze_all():
    data = request.json
    quiz_score = data.get('quiz_data', {}).get('correct_answers')
    visual_level = data.get('visual_game_data', {}).get('correct_sequence')
    reaction_time = data.get('speed_game_data', {}).get('reaction_time')
    user_id = current_user.id # Get the current user's ID

    # Save data to database
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO results (user_id, quiz_score, visual_level, reaction_time) VALUES (?, ?, ?, ?)",
                       (user_id, quiz_score, visual_level, reaction_time))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Eroare la salvarea in baza de date: {e}")
        return jsonify({"error": "Failed to save results"}), 500

    # Your existing analysis logic...
    overall_assessment = "Your overall assessment here."
    response = {
        "overall_assessment": overall_assessment,
        "quiz_result": f"Scor la quiz: {quiz_score} din 3.",
        "visual_memory_result": f"Nivel de memorie vizuala atins: {visual_level}.",
        "reaction_time_result": f"Timp de reactie: {reaction_time} ms."
    }
    
    return jsonify(response)

@app.route('/api/results', methods=['GET'])
@login_required
def get_results():
    user_id = current_user.id # Get the current user's ID
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Fetch only the current user's results
    cursor.execute("SELECT * FROM results WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    results = cursor.fetchall()
    conn.close()

    results_list = [dict(row) for row in results]
    
    return jsonify(results_list)

@app.route('/api/analyze_mri', methods=['POST'])
@login_required
def analyze_mri():
    # Placeholder for MRI analysis
    return jsonify({"mri_analysis": "Nu au fost detectate anomalii majore."})


if __name__ == '__main__':
    app.run(debug=True)