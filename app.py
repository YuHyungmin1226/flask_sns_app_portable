import os
import datetime
import pytz
import logging
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for, flash, 
                   session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user, 
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import desc

# Local utils
from utils.url_utils import get_url_preview

# --- 2. Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 3. Flask App Initialization and Configuration ---
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = 'your_very_secret_key_that_is_long_and_random'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'sns.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=60)

# --- 4. Database and Login Manager Initialization ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None

# --- 5. Global Variables ---
KST = pytz.timezone('Asia/Seoul')
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = datetime.timedelta(minutes=15)

# --- 6. Helper Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def make_session_permanent():
    session.permanent = True


# --- 7. Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='author', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url_preview_title = db.Column(db.String(200), nullable=True)
    url_preview_description = db.Column(db.Text, nullable=True)
    url_preview_image = db.Column(db.String(300), nullable=True)
    url_preview_url = db.Column(db.String(300), nullable=True)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# --- 8. Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_utility_processor():
    def get_kst_time(dt):
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        return dt.astimezone(KST)
    
    return {
        'now': datetime.datetime.now(KST),
        'get_kst_time': get_kst_time
    }


# --- 10. Route Definitions ---

# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('이미 존재하는 사용자 이름입니다.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.is_locked:
            if user.locked_until and user.locked_until > datetime.datetime.now(pytz.utc):
                remaining_time = (user.locked_until - datetime.datetime.now(pytz.utc)).seconds // 60
                flash(f'계정이 잠겼습니다. {remaining_time}분 후에 다시 시도해주세요.', 'danger')
                return redirect(url_for('login'))
            else:
                user.is_locked = False
                user.locked_until = None
                LOGIN_ATTEMPTS.pop(username, None)
                db.session.commit()
        if user and user.check_password(password):
            remember_me = True if 'remember' in request.form else False
            login_user(user, remember=remember_me)
            LOGIN_ATTEMPTS.pop(username, None) # 성공 시 시도 횟수 초기화
            return redirect(url_for('index'))
        else:
            if user:
                LOGIN_ATTEMPTS[username] = LOGIN_ATTEMPTS.get(username, 0) + 1
                if LOGIN_ATTEMPTS[username] >= MAX_LOGIN_ATTEMPTS:
                    user.is_locked = True
                    user.locked_until = datetime.datetime.now(pytz.utc) + LOCKOUT_DURATION
                    db.session.commit()
                    flash('로그인 5회 실패로 계정이 15분간 잠깁니다.', 'danger')
                else:
                    remaining_attempts = MAX_LOGIN_ATTEMPTS - LOGIN_ATTEMPTS[username]
                    flash(f'로그인 정보가 올바르지 않습니다. (남은 시도: {remaining_attempts}회)', 'danger')
            else:
                flash('존재하지 않는 사용자입니다.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Content Routes ---
@app.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    posts_pagination = Post.query.order_by(desc(Post.timestamp)).paginate(page=page, per_page=10)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('_posts_list.html', posts_pagination=posts_pagination)
        
    return render_template('index.html', posts_pagination=posts_pagination)

@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        content = request.form['content']
        if not content:
            flash('내용을 입력해주세요.', 'danger')
            return redirect(request.url)
        post = Post(content=content, author=current_user)
        try:
            preview_data = get_url_preview(content)
            if preview_data:
                post.url_preview_title = preview_data['title']
                post.url_preview_description = preview_data['description']
                post.url_preview_image = preview_data['image']
                post.url_preview_url = preview_data['url']
        except Exception as e:
            logging.error(f"URL preview generation failed: {e}")
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_post.html')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        comment_content = request.form['content']
        if comment_content:
            comment = Comment(content=comment_content, author=current_user, post=post)
            db.session.add(comment)
            db.session.commit()
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('view_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin:
        flash('삭제 권한이 없습니다.', 'danger')
        return redirect(url_for('view_post', post_id=post.id))
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    if comment.author != current_user and not current_user.is_admin:
        flash('삭제 권한이 없습니다.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('view_post', post_id=post_id))

# --- User Profile Routes ---
@app.route('/profile/<username>')
@login_required
def profile(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts_pagination = Post.query.filter_by(author=user).order_by(desc(Post.timestamp)).paginate(page=page, per_page=10)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('_posts_list.html', posts_pagination=posts_pagination)
        
    return render_template('profile.html', user=user, posts_pagination=posts_pagination)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        if not current_user.check_password(current_password):
            flash('현재 비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('change_password'))
        current_user.set_password(new_password)
        db.session.commit()
        return redirect(url_for('profile', username=current_user.username))
    return render_template('change_password.html')

# --- Admin Routes ---
@app.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.is_admin:
        flash('관리자 계정은 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('admin'))
    # Cascade delete should handle posts and comments
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('admin'))

# --- 11. Standalone Functions ---
def create_database_and_admin():
    """Creates database and initial admin user."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            logging.info("Default admin user created.")