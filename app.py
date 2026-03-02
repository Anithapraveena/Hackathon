import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from functools import wraps
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'devtrack_secret_key_2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Database initialization
DB_NAME = 'devtrack.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('student', 'guide', 'coordinator')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Teams table
    c.execute('''CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Team members junction table
    c.execute('''CREATE TABLE IF NOT EXISTS team_members (
        team_id INTEGER,
        user_id INTEGER,
        PRIMARY KEY (team_id, user_id),
        FOREIGN KEY (team_id) REFERENCES teams(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Projects table
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        team_id INTEGER,
        guide_id INTEGER,
        status TEXT DEFAULT 'active' CHECK(status IN ('active', 'completed', 'archived')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (team_id) REFERENCES teams(id),
        FOREIGN KEY (guide_id) REFERENCES users(id)
    )''')
    
    # Tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'todo' CHECK(status IN ('todo', 'in_progress', 'review', 'done')),
        priority TEXT DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high', 'urgent')),
        assigned_to INTEGER,
        created_by INTEGER,
        due_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (assigned_to) REFERENCES users(id),
        FOREIGN KEY (created_by) REFERENCES users(id)
    )''')
    
    # Bugs table
    c.execute('''CREATE TABLE IF NOT EXISTS bugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
        status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'resolved', 'closed')),
        reported_by INTEGER,
        assigned_to INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (reported_by) REFERENCES users(id),
        FOREIGN KEY (assigned_to) REFERENCES users(id)
    )''')
    
    # Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_type TEXT NOT NULL CHECK(content_type IN ('task', 'bug')),
        content_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Milestones table
    c.execute('''CREATE TABLE IF NOT EXISTS milestones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        due_date DATE,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'completed')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )''')
    
    # Submissions table
    c.execute('''CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        milestone_id INTEGER,
        title TEXT NOT NULL,
        file_path TEXT,
        description TEXT,
        submitted_by INTEGER,
        feedback TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (milestone_id) REFERENCES milestones(id),
        FOREIGN KEY (submitted_by) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                      (username, email, hash_password(password), role))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and user['password'] == hash_password(password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    role = session['role']
    db = get_db()
    
    if role == 'student':
        # Get projects where user is a team member
        projects = db.execute('''
            SELECT p.*, t.name as team_name 
            FROM projects p
            JOIN team_members tm ON p.team_id = tm.team_id
            LEFT JOIN teams t ON p.team_id = t.id
            WHERE tm.user_id = ? AND p.status = 'active'
        ''', (user_id,)).fetchall()
        
        # Get assigned tasks
        tasks = db.execute('''
            SELECT t.*, p.name as project_name
            FROM tasks t
            JOIN projects p ON t.project_id = p.id
            WHERE t.assigned_to = ? AND t.status != 'done'
            ORDER BY t.due_date
        ''', (user_id,)).fetchall()
        
        # Get assigned bugs
        bugs = db.execute('''
            SELECT b.*, p.name as project_name
            FROM bugs b
            JOIN projects p ON b.project_id = p.id
            WHERE b.assigned_to = ? AND b.status != 'closed'
            ORDER BY b.created_at DESC
        ''', (user_id,)).fetchall()
        
    elif role == 'guide':
        # Get projects where user is the guide
        projects = db.execute('''
            SELECT p.*, t.name as team_name
            FROM projects p
            LEFT JOIN teams t ON p.team_id = t.id
            WHERE p.guide_id = ?
        ''', (user_id,)).fetchall()
        
        tasks = []
        bugs = []
        
    else:  # coordinator
        # Get all active projects
        projects = db.execute('''
            SELECT p.*, t.name as team_name, u.username as guide_name
            FROM projects p
            LEFT JOIN teams t ON p.team_id = t.id
            LEFT JOIN users u ON p.guide_id = u.id
            WHERE p.status = 'active'
        ''').fetchall()
        
        tasks = []
        bugs = []
    
    return render_template('dashboard.html', projects=projects, tasks=tasks, bugs=bugs)

# Project Routes
@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
@role_required('student')
def create_project():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        team_name = request.form['team_name']
        
        db = get_db()
        
        # Create team
        db.execute('INSERT INTO teams (name) VALUES (?)', (team_name,))
        team_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Add current user to team
        db.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)',
                  (team_id, session['user_id']))
        
        # Create project
        db.execute('''INSERT INTO projects (name, description, team_id, guide_id) 
                      VALUES (?, ?, ?, NULL)''',
                  (name, description, team_id))
        
        db.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_project.html')

@app.route('/projects/<int:project_id>')
@login_required
def view_project(project_id):
    db = get_db()
    project = db.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
    
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get tasks
    tasks = db.execute('''
        SELECT t.*, u.username as assignee_name
        FROM tasks t
        LEFT JOIN users u ON t.assigned_to = u.id
        WHERE t.project_id = ?
        ORDER BY t.status, t.priority
    ''', (project_id,)).fetchall()
    
    # Get bugs
    bugs = db.execute('''
        SELECT b.*, u.username as assignee_name, r.username as reporter_name
        FROM bugs b
        LEFT JOIN users u ON b.assigned_to = u.id
        LEFT JOIN users r ON b.reported_by = u.id
        WHERE b.project_id = ?
        ORDER BY b.severity, b.status
    ''', (project_id,)).fetchall()
    
    # Get milestones
    milestones = db.execute('''
        SELECT * FROM milestones WHERE project_id = ? ORDER BY due_date
    ''', (project_id,)).fetchall()
    
    # Get submissions
    submissions = db.execute('''
        SELECT s.*, u.username as submitter_name, m.title as milestone_title
        FROM submissions s
        LEFT JOIN users u ON s.submitted_by = u.id
        LEFT JOIN milestones m ON s.milestone_id = m.id
        WHERE s.project_id = ?
        ORDER BY s.submitted_at DESC
    ''', (project_id,)).fetchall()
    
    # Organize tasks by status for Kanban
    kanban_tasks = {
        'todo': [t for t in tasks if t['status'] == 'todo'],
        'in_progress': [t for t in tasks if t['status'] == 'in_progress'],
        'review': [t for t in tasks if t['status'] == 'review'],
        'done': [t for t in tasks if t['status'] == 'done']
    }
    
    # Get team members
    team_members = db.execute('''
        SELECT u.id, u.username, u.email, u.role
        FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
    ''', (project['team_id'],)).fetchall() if project['team_id'] else []
    
    return render_template('project.html', project=project, kanban_tasks=kanban_tasks, 
                           bugs=bugs, milestones=milestones, submissions=submissions,
                           team_members=team_members)

# Task Routes
@app.route('/projects/<int:project_id>/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task(project_id):
    db = get_db()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        assigned_to = request.form.get('assigned_to')
        due_date = request.form.get('due_date')
        
        db.execute('''INSERT INTO tasks (project_id, title, description, priority, assigned_to, created_by, due_date)
                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (project_id, title, description, priority, assigned_to, session['user_id'], due_date))
        db.commit()
        flash('Task created successfully!', 'success')
        return redirect(url_for('view_project', project_id=project_id))
    
    # Get project team members for assignment
    project = db.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
    team_members = db.execute('''
        SELECT u.id, u.username FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
    ''', (project['team_id'],)).fetchall() if project['team_id'] else []
    
    return render_template('create_task.html', project_id=project_id, team_members=team_members)

@app.route('/tasks/<int:task_id>/update', methods=['POST'])
@login_required
def update_task(task_id):
    db = get_db()
    status = request.form['status']
    priority = request.form.get('priority')
    assigned_to = request.form.get('assigned_to')
    
    if priority:
        db.execute('UPDATE tasks SET priority = ? WHERE id = ?', (priority, task_id))
    if assigned_to:
        db.execute('UPDATE tasks SET assigned_to = ? WHERE id = ?', (assigned_to, task_id))
    db.execute('UPDATE tasks SET status = ? WHERE id = ?', (status, task_id))
    db.commit()
    
    task = db.execute('SELECT project_id FROM tasks WHERE id = ?', (task_id,)).fetchone()
    flash('Task updated successfully!', 'success')
    return redirect(url_for('view_project', project_id=task['project_id']))

@app.route('/tasks/<int:task_id>/delete')
@login_required
def delete_task(task_id):
    db = get_db()
    task = db.execute('SELECT project_id FROM tasks WHERE id = ?', (task_id,)).fetchone()
    db.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    db.commit()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('view_project', project_id=task['project_id']))

# Bug Routes
@app.route('/projects/<int:project_id>/bugs/create', methods=['GET', 'POST'])
@login_required
def create_bug(project_id):
    db = get_db()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        severity = request.form['severity']
        assigned_to = request.form.get('assigned_to')
        
        db.execute('''INSERT INTO bugs (project_id, title, description, severity, reported_by, assigned_to)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                  (project_id, title, description, severity, session['user_id'], assigned_to))
        db.commit()
        flash('Bug reported successfully!', 'success')
        return redirect(url_for('view_project', project_id=project_id))
    
    project = db.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
    team_members = db.execute('''
        SELECT u.id, u.username FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
    ''', (project['team_id'],)).fetchall() if project['team_id'] else []
    
    return render_template('create_bug.html', project_id=project_id, team_members=team_members)

@app.route('/bugs/<int:bug_id>/update', methods=['POST'])
@login_required
def update_bug(bug_id):
    db = get_db()
    status = request.form['status']
    assigned_to = request.form.get('assigned_to')
    
    if assigned_to:
        db.execute('UPDATE bugs SET assigned_to = ? WHERE id = ?', (assigned_to, bug_id))
    
    if status == 'closed' or status == 'resolved':
        db.execute('UPDATE bugs SET status = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?', 
                  (status, bug_id))
    else:
        db.execute('UPDATE bugs SET status = ? WHERE id = ?', (status, bug_id))
    db.commit()
    
    bug = db.execute('SELECT project_id FROM bugs WHERE id = ?', (bug_id,)).fetchone()
    flash('Bug updated successfully!', 'success')
    return redirect(url_for('view_project', project_id=bug['project_id']))

# Comment Routes
@app.route('/comments/<content_type>/<int:content_id>/add', methods=['POST'])
@login_required
def add_comment(content_type, content_id):
    content = request.form['content']
    
    db = get_db()
    db.execute('''INSERT INTO comments (content_type, content_id, user_id, content)
                  VALUES (?, ?, ?, ?)''',
              (content_type, content_id, session['user_id'], content))
    db.commit()
    flash('Comment added successfully!', 'success')
    
    # Redirect back to the appropriate page
    if content_type == 'task':
        task = db.execute('SELECT project_id FROM tasks WHERE id = ?', (content_id,)).fetchone()
        return redirect(url_for('view_project', project_id=task['project_id']))
    else:
        bug = db.execute('SELECT project_id FROM bugs WHERE id = ?', (content_id,)).fetchone()
        return redirect(url_for('view_project', project_id=bug['project_id']))

@app.route('/comments/<int:comment_id>/delete')
@login_required
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    
    if comment['user_id'] != session['user_id']:
        flash('You can only delete your own comments.', 'error')
        return redirect(url_for('dashboard'))
    
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash('Comment deleted successfully!', 'success')
    
    if comment['content_type'] == 'task':
        task = db.execute('SELECT project_id FROM tasks WHERE id = ?', (comment['content_id'])).fetchone()
        return redirect(url_for('view_project', project_id=task['project_id']))
    else:
        bug = db.execute('SELECT project_id FROM bugs WHERE id = ?', (comment['content_id'])).fetchone()
        return redirect(url_for('view_project', project_id=bug['project_id']))

# Milestone Routes
@app.route('/projects/<int:project_id>/milestones/create', methods=['GET', 'POST'])
@login_required
def create_milestone(project_id):
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        
        db = get_db()
        db.execute('''INSERT INTO milestones (project_id, title, description, due_date)
                      VALUES (?, ?, ?, ?)''',
                  (project_id, title, description, due_date))
        db.commit()
        flash('Milestone created successfully!', 'success')
        return redirect(url_for('view_project', project_id=project_id))
    
    return render_template('create_milestone.html', project_id=project_id)

@app.route('/milestones/<int:milestone_id>/update', methods=['POST'])
@login_required
def update_milestone(milestone_id):
    db = get_db()
    status = request.form['status']
    
    db.execute('UPDATE milestones SET status = ? WHERE id = ?', (status, milestone_id))
    db.commit()
    
    milestone = db.execute('SELECT project_id FROM milestones WHERE id = ?', (milestone_id,)).fetchone()
    flash('Milestone updated successfully!', 'success')
    return redirect(url_for('view_project', project_id=milestone['project_id']))

# Submission Routes
@app.route('/projects/<int:project_id>/submissions/create', methods=['GET', 'POST'])
@login_required
def create_submission(project_id):
    db = get_db()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        milestone_id = request.form.get('milestone_id')
        file = request.files.get('file')
        
        file_path = None
        if file and file.filename:
            filename = f"{datetime.now().timestamp()}_{file.filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_path = filename
        
        db.execute('''INSERT INTO submissions (project_id, milestone_id, title, description, file_path, submitted_by)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                  (project_id, milestone_id, title, description, file_path, session['user_id']))
        db.commit()
        flash('Submission created successfully!', 'success')
        return redirect(url_for('view_project', project_id=project_id))
    
    milestones = db.execute('SELECT * FROM milestones WHERE project_id = ?', (project_id,)).fetchall()
    return render_template('create_submission.html', project_id=project_id, milestones=milestones)

@app.route('/submissions/<int:submission_id>/feedback', methods=['POST'])
@login_required
def add_feedback(submission_id):
    db = get_db()
    feedback = request.form['feedback']
    status = request.form['status']
    
    db.execute('UPDATE submissions SET feedback = ?, status = ? WHERE id = ?',
              (feedback, status, submission_id))
    db.commit()
    
    submission = db.execute('SELECT project_id FROM submissions WHERE id = ?', (submission_id,)).fetchone()
    flash('Feedback added successfully!', 'success')
    return redirect(url_for('view_project', project_id=submission['project_id']))

# API Routes for Kanban
@app.route('/api/tasks/<int:task_id>/move', methods=['POST'])
@login_required
def move_task(task_id):
    db = get_db()
    status = request.json['status']
    
    db.execute('UPDATE tasks SET status = ? WHERE id = ?', (status, task_id))
    db.commit()
    
    return {'success': True}

# Team Management
@app.route('/projects/<int:project_id>/team/add', methods=['POST'])
@login_required
def add_team_member(project_id):
    db = get_db()
    username = request.form['username']
    
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    project = db.execute('SELECT team_id FROM projects WHERE id = ?', (project_id,)).fetchone()
    
    if user and project and project['team_id']:
        try:
            db.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)',
                      (project['team_id'], user['id']))
            db.commit()
            flash(f'{username} added to the team!', 'success')
        except sqlite3.IntegrityError:
            flash('User is already a team member.', 'error')
    else:
        flash('User or project not found.', 'error')
    
    return redirect(url_for('view_project', project_id=project_id))

# Guide Assignment
@app.route('/projects/<int:project_id>/assign_guide', methods=['POST'])
@login_required
@role_required('coordinator')
def assign_guide(project_id):
    db = get_db()
    guide_id = request.form['guide_id']
    
    db.execute('UPDATE projects SET guide_id = ? WHERE id = ?', (guide_id, project_id))
    db.commit()
    flash('Guide assigned successfully!', 'success')
    return redirect(url_for('view_project', project_id=project_id))

if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        init_db()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
