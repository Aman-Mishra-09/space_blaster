"""
Space Blaster - Flask Backend
Features: User auth, score tracking, leaderboard, game config
"""

import os
import hashlib
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)

# ─── App Configuration ───────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DATABASE = os.path.join(os.path.dirname(__file__), 'game.db')

# ─── Database Helpers ─────────────────────────────────────────────────
def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            salt        TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now')),
            games_played INTEGER DEFAULT 0,
            total_kills  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            score       INTEGER NOT NULL,
            level       INTEGER DEFAULT 1,
            kills       INTEGER DEFAULT 0,
            duration    REAL    DEFAULT 0,
            played_at   TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS achievements (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            name        TEXT    NOT NULL,
            description TEXT,
            unlocked_at TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, name)
        );

        CREATE INDEX IF NOT EXISTS idx_scores_user   ON scores(user_id);
        CREATE INDEX IF NOT EXISTS idx_scores_score   ON scores(score DESC);
        CREATE INDEX IF NOT EXISTS idx_scores_date    ON scores(played_at);
    ''')
    conn.commit()
    conn.close()


def hash_password(password, salt=None):
    """Hash password with salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt.encode(), 100_000
    )
    return hashed.hex(), salt


# ─── Auth Decorator ───────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Page Routes ──────────────────────────────────────────────────────
@app.route('/')
def index():
    """Serve the game page."""
    return render_template('index.html')


# ─── Auth API ─────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(username) < 3 or len(username) > 20:
        return jsonify({'error': 'Username must be 3-20 characters'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    if not username.isalnum():
        return jsonify({'error': 'Username must be alphanumeric'}), 400

    hashed, salt = hash_password(password)

    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
            (username, hashed, salt)
        )
        conn.commit()
        user_id = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()['id']
        conn.close()

        session['user_id'] = user_id
        session['username'] = username

        return jsonify({
            'message': 'Registration successful',
            'username': username
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409


@app.route('/api/login', methods=['POST'])
def login():
    """Log in a user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    hashed, _ = hash_password(password, user['salt'])
    if hashed != user['password']:
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']

    return jsonify({
        'message': 'Login successful',
        'username': user['username']
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    """Log out the current user."""
    session.clear()
    return jsonify({'message': 'Logged out'})


@app.route('/api/me')
def me():
    """Get current user info."""
    if 'user_id' not in session:
        return jsonify({'logged_in': False})

    conn = get_db()
    user = conn.execute(
        'SELECT id, username, games_played, total_kills, created_at '
        'FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()

    best = conn.execute(
        'SELECT MAX(score) as best_score, MAX(level) as best_level '
        'FROM scores WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()

    achievements = conn.execute(
        'SELECT name, description, unlocked_at FROM achievements '
        'WHERE user_id = ? ORDER BY unlocked_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return jsonify({
        'logged_in': True,
        'username': user['username'],
        'games_played': user['games_played'],
        'total_kills': user['total_kills'],
        'best_score': best['best_score'] or 0,
        'best_level': best['best_level'] or 0,
        'achievements': [dict(a) for a in achievements]
    })


# ─── Score API ────────────────────────────────────────────────────────
@app.route('/api/score', methods=['POST'])
@login_required
def submit_score():
    """Submit a game score."""
    data = request.get_json()
    score = data.get('score', 0)
    level = data.get('level', 1)
    kills = data.get('kills', 0)
    duration = data.get('duration', 0)

    if not isinstance(score, int) or score < 0:
        return jsonify({'error': 'Invalid score'}), 400

    conn = get_db()

    # Insert score
    conn.execute(
        'INSERT INTO scores (user_id, score, level, kills, duration) '
        'VALUES (?, ?, ?, ?, ?)',
        (session['user_id'], score, level, kills, duration)
    )

    # Update user stats
    conn.execute(
        'UPDATE users SET games_played = games_played + 1, '
        'total_kills = total_kills + ? WHERE id = ?',
        (kills, session['user_id'])
    )

    # ── Check & unlock achievements ──
    user = conn.execute(
        'SELECT games_played, total_kills FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()

    achievement_checks = [
        (score >= 1000,   'Score Rookie',    'Score 1,000 points'),
        (score >= 5000,   'Score Pro',       'Score 5,000 points'),
        (score >= 10000,  'Score Master',    'Score 10,000 points'),
        (score >= 50000,  'Score Legend',    'Score 50,000 points'),
        (kills >= 50,     'Hunter',          'Kill 50 enemies in one game'),
        (kills >= 100,    'Destroyer',       'Kill 100 enemies in one game'),
        (level >= 5,      'Survivor',        'Reach level 5'),
        (level >= 10,     'Veteran',         'Reach level 10'),
        (user['games_played'] >= 10,  'Dedicated',  'Play 10 games'),
        (user['games_played'] >= 50,  'Addicted',   'Play 50 games'),
        (user['total_kills'] >= 500,  'Warlord',    'Kill 500 total enemies'),
        (duration >= 300,  'Endurance',      'Survive 5 minutes'),
    ]

    new_achievements = []
    for condition, name, description in achievement_checks:
        if condition:
            try:
                conn.execute(
                    'INSERT INTO achievements (user_id, name, description) '
                    'VALUES (?, ?, ?)',
                    (session['user_id'], name, description)
                )
                new_achievements.append({'name': name, 'description': description})
            except sqlite3.IntegrityError:
                pass  # Already unlocked

    conn.commit()

    # Get rank
    rank = conn.execute(
        'SELECT COUNT(*) + 1 as rank FROM '
        '(SELECT user_id, MAX(score) as best FROM scores '
        'GROUP BY user_id) WHERE best > ?',
        (score,)
    ).fetchone()['rank']

    conn.close()

    return jsonify({
        'message': 'Score submitted',
        'rank': rank,
        'new_achievements': new_achievements
    })


# ─── Leaderboard API ─────────────────────────────────────────────────
@app.route('/api/leaderboard')
def leaderboard():
    """Get top scores leaderboard."""
    period = request.args.get('period', 'all')  # all, today, week
    limit = min(int(request.args.get('limit', 20)), 100)

    conn = get_db()

    date_filter = ''
    if period == 'today':
        date_filter = "AND s.played_at >= date('now')"
    elif period == 'week':
        date_filter = "AND s.played_at >= date('now', '-7 days')"

    query = f'''
        SELECT u.username, MAX(s.score) as best_score,
               MAX(s.level) as best_level, SUM(s.kills) as total_kills,
               COUNT(s.id) as games
        FROM scores s
        JOIN users u ON s.user_id = u.id
        WHERE 1=1 {date_filter}
        GROUP BY s.user_id
        ORDER BY best_score DESC
        LIMIT ?
    '''

    rows = conn.execute(query, (limit,)).fetchall()
    conn.close()

    return jsonify({
        'period': period,
        'leaderboard': [
            {
                'rank': i + 1,
                'username': row['username'],
                'score': row['best_score'],
                'level': row['best_level'],
                'total_kills': row['total_kills'],
                'games': row['games']
            }
            for i, row in enumerate(rows)
        ]
    })


@app.route('/api/stats')
def global_stats():
    """Get global game statistics."""
    conn = get_db()
    stats = conn.execute('''
        SELECT
            COUNT(DISTINCT user_id) as total_players,
            COUNT(*) as total_games,
            SUM(kills) as total_kills,
            MAX(score) as highest_score,
            AVG(score) as avg_score,
            MAX(level) as highest_level,
            SUM(duration) as total_playtime
        FROM scores
    ''').fetchone()
    conn.close()

    return jsonify({
        'total_players': stats['total_players'] or 0,
        'total_games': stats['total_games'] or 0,
        'total_kills': stats['total_kills'] or 0,
        'highest_score': stats['highest_score'] or 0,
        'avg_score': round(stats['avg_score'] or 0),
        'highest_level': stats['highest_level'] or 0,
        'total_playtime': round(stats['total_playtime'] or 0)
    })


# ─── Initialize & Run ────────────────────────────────────────────────
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Space Blaster server running at http://localhost:{port}")
    app.run(debug=True, host='0.0.0.0', port=port)