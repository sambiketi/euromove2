import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
from PIL import Image
import secrets

# ========== CONFIG ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Max 5MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Mail config (for forgot password)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'
mail = Mail(app)

# ========== DATABASE MODELS ==========
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

class Programme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(100), nullable=False)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_field = db.Column(db.String(100), nullable=False)
    job_name = db.Column(db.String(100), nullable=False)

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    admin_answer = db.Column(db.Text)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

# ========== LOGIN MANAGER ==========
@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# ========== ROUTES ==========

# ---- FRONTEND ----
@app.route('/')
def index():
    admin_posts = Post.query.order_by(Post.date_posted.desc()).all()
    programmes = {}
    for p in Programme.query.all():
        programmes.setdefault(p.field, []).append(p.course)
    jobs = {}
    for j in Job.query.all():
        jobs.setdefault(j.job_field, []).append(j.job_name)
    faqs = FAQ.query.order_by(FAQ.date_submitted.desc()).all()
    logo_filename = "logo.png"  # Replace with actual logo filename in /static/img/
    return render_template('euromove.html', admin_posts=admin_posts,
                           programmes=programmes, jobs=jobs, faqs=faqs,
                           logo_filename=logo_filename)

# ---- FORM HANDLERS ----
@app.route('/submit_programme', methods=['POST'])
def submit_programme():
    flash('Programme application submitted! We will get back to you soon.', 'success')
    return redirect(url_for('index'))

@app.route('/submit_job', methods=['POST'])
def submit_job():
    flash('Job application submitted! We will get back to you soon.', 'success')
    return redirect(url_for('index'))

@app.route('/submit_question', methods=['POST'])
def submit_question():
    name = request.form['name']
    email = request.form['email']
    question = request.form['question']
    faq = FAQ(user_name=name, email=email, question_text=question)
    db.session.add(faq)
    db.session.commit()
    flash('Question submitted! We will get back to you soon.', 'success')
    return redirect(url_for('index'))

# ---- ADMIN LOGIN ----
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

# ---- ADMIN DASHBOARD ----
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    programmes = {}
    for p in Programme.query.all():
        programmes.setdefault(p.field, []).append(p.course)
    jobs = {}
    for j in Job.query.all():
        jobs.setdefault(j.job_field, []).append(j.job_name)
    faqs = FAQ.query.order_by(FAQ.date_submitted.desc()).all()
    return render_template('admin_dashboard.html', programmes=programmes, jobs=jobs, faqs=faqs)

# ---- POST CONTENT ----
@app.route('/admin/post_content', methods=['POST'])
@login_required
def post_content():
    title = request.form['title']
    content = request.form['content']
    image_file = request.files.get('image')
    filename = None
    if image_file:
        ext = os.path.splitext(image_file.filename)[1]
        filename = secrets.token_hex(8) + ext
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        img = Image.open(image_file)
        img.save(filepath, optimize=True, quality=70)
    post = Post(title=title, content=content, image=filename)
    db.session.add(post)
    db.session.commit()
    flash('Post added successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# ---- ADD PROGRAMME ----
@app.route('/admin/add_programme', methods=['POST'])
@login_required
def add_programme():
    field = request.form['field']
    course = request.form['course']
    db.session.add(Programme(field=field, course=course))
    db.session.commit()
    flash('Programme added successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# ---- ADD JOB ----
@app.route('/admin/add_job', methods=['POST'])
@login_required
def add_job():
    job_field = request.form['job_field']
    job_name = request.form['job_name']
    db.session.add(Job(job_field=job_field, job_name=job_name))
    db.session.commit()
    flash('Job added successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# ---- ANSWER FAQ ----
@app.route('/admin/answer_faq/<int:faq_id>', methods=['POST'])
@login_required
def answer_faq(faq_id):
    answer = request.form['answer']
    faq = FAQ.query.get(faq_id)
    faq.admin_answer = answer
    db.session.commit()
    flash('FAQ answered successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# ---- CHANGE PASSWORD ----
@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_password():
    current = request.form['current_password']
    new_pass = request.form['new_password']
    if current and new_pass and current_user.check_password(current):
        current_user.password_hash = generate_password_hash(new_pass)
        db.session.commit()
        flash('Password changed successfully', 'success')
    else:
        flash('Current password is incorrect', 'danger')
    return redirect(url_for('admin_dashboard'))

# ---- FORGOT PASSWORD ----
@app.route('/admin/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        admin = Admin.query.filter_by(email=email).first()
        if admin:
            token = secrets.token_urlsafe(16)
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Euromove Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)
            flash('Password reset link sent to your email', 'success')
        else:
            flash('Email not registered', 'danger')
    return '''
        <form method="post">
        <input name="email" placeholder="Enter your email" required>
        <button type="submit">Send Reset Link</button>
        </form>
    '''
#Create upload logo route
import os
from flask import request, redirect, url_for, flash
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png','jpeg','jpg','gif'}
def allowed_file(filename):
    return'.'in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/upload_logo',
methods=['POST'])
def upload_logo():
    file=request.files.get('logo')
    if not file or file.filename == '':
        flash('No file selected')
        return redirect(request.referrer)
    if not allowed_file(file.filename):
        flash('invalid file type')
        return redirect(request.referrer)
        filename='site_logo.' + file.filename.rsplit('.',1)[1],lower()
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'],filename)
    os.makedirs(app.config['UPLOAD_FOLDER'],exist_ok=True)
    file.save(upload_path)
    flash('logo uploaded succesfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password/<token>', methods=['GET','POST'])
def reset_password(token):
    if request.method == 'POST':
        new_pass = request.form['new_password']
        admin = Admin.query.first()  # Simplified: assign to first admin
        admin.password_hash = generate_password_hash(new_pass)
        db.session.commit()
        flash('Password reset successfully', 'success')
        return redirect(url_for('admin_login'))
    return '''
        <form method="post">
        <input name="new_password" placeholder="Enter new password" required>
        <button type="submit">Reset Password</button>
        </form>
    '''

# ========== INIT DB ==========
@app.before_request
def create_tables():
    db.create_all()
    if not Admin.query.first():
        # Create default admin
        hashed_pw = generate_password_hash('password')
        db.session.add(Admin(username='admin', email='admin@euromove.com', password_hash=hashed_pw))
        db.session.commit()

# ========== RUN ==========
if __name__ == "__main__":
    app.run(debug=True)