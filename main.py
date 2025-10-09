import os
import re
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, Date, ForeignKey
from typing import List
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-secret")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///local.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ----------------------------
# Talisman: HTTPS + HSTS + CSP
# ----------------------------
csp = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "https://cdn.jsdelivr.net",        # Bootstrap CSS y Bootstrap Icons
        "https://fonts.googleapis.com",    # Google Fonts
        "https://cdnjs.cloudflare.com"     # Font Awesome
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com",       # Google Fonts
        "https://cdn.jsdelivr.net"         # Bootstrap Icons fonts
    ],
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net"         # Bootstrap JS bundle
    ]
}

if os.environ.get("FLASK_ENV") == "production":
    Talisman(
        app,
        content_security_policy=csp,
        force_https=True,
        strict_transport_security=True
    )


# -------------------- Models --------------------

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    todo_lists: Mapped[List["TodoList"]] = relationship("TodoList", back_populates="owner")


class TodoList(db.Model):
    __tablename__ = "todo_lists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), default="My to-do list")
    tasks: Mapped[List["Task"]] = relationship("Task", back_populates="todo_list", cascade="all, delete-orphan")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner: Mapped[User] = relationship("User", back_populates="todo_lists")
    session_id: Mapped[str] = mapped_column(String(100), nullable=True)


class Task(db.Model):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    date: Mapped[Date] = mapped_column(Date, nullable=True)
    is_done: Mapped[bool] = mapped_column(Boolean, default=False)
    color: Mapped[str] = mapped_column(String(20), default="white")
    todo_list_id: Mapped[int] = mapped_column(ForeignKey("todo_lists.id"), nullable=False)
    todo_list: Mapped[TodoList] = relationship("TodoList", back_populates="tasks")


# -------------------- Flask-Login --------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- Helper Functions --------------------

def get_guest_session_id():
    if "guest_id" not in session:
        session["guest_id"] = str(uuid.uuid4())
    return session["guest_id"]


def get_current_owner():
    """Return (owner_id, session_id) tuple depending on login status."""
    if current_user.is_authenticated:
        return current_user.id, None
    else:
        return None, get_guest_session_id()


def get_user_list(list_id: int) -> TodoList | None:
    """Get a user's list (authenticated or guest) by id, return None if not found."""
    owner_id, session_id = get_current_owner()
    if owner_id:
        return TodoList.query.filter_by(id=list_id, owner_id=owner_id).first()
    else:
        return TodoList.query.filter_by(id=list_id, session_id=session_id).first()


def get_task_or_404(task_id: int) -> Task:
    task = Task.query.get_or_404(task_id)
    owner_id, session_id = get_current_owner()
    if owner_id and task.todo_list.owner_id != owner_id:
        abort(404)
    if session_id and task.todo_list.session_id != session_id:
        abort(404)
    return task


def create_or_update_list(list_id: int | None, title: str | None = None) -> TodoList:
    """
    Obtiene o crea una lista para el usuario actual o guest.
    - Si list_id existe, actualiza el título solo si se pasó uno.
    - Si no existe, crea una nueva lista con title o default.
    - Devuelve la lista.
    """
    todo_list = get_user_list(list_id)
    owner_id, session_id = get_current_owner()

    if not todo_list:
        todo_list = TodoList(
            title=title if title else "My to-do list",
            owner=current_user if owner_id else None,
            session_id=None if owner_id else session_id
        )
        db.session.add(todo_list)
    else:
        if title is not None:
            todo_list.title = title  # solo actualizar si title fue pasado

    db.session.commit()
    return todo_list


# -------------------- Routes --------------------

@app.route('/')
@csrf.exempt
def index():
    owner_id, session_id = get_current_owner()
    all_lists = (TodoList.query.filter_by(owner_id=owner_id).order_by(TodoList.title).all()
                 if owner_id
                 else TodoList.query.filter_by(session_id=session_id).order_by(TodoList.title).all())
    list_id = request.args.get("list_id", type=int)
    todo_list = get_user_list(list_id) if list_id else None
    if not todo_list and all_lists:
        todo_list = all_lists[0]
    return render_template("index.html", todo_list=todo_list, all_lists=all_lists)


# ------------ List Actions ------------

@app.route('/save-list', methods=['POST'])
@csrf.exempt
def save_list():
    list_id = request.form.get("list_id", type=int)
    list_name = request.form.get("list_name") or "My to-do list"
    todo_list = create_or_update_list(list_id, list_name)

    return redirect(url_for('index', list_id=todo_list.id))


@app.route('/delete-list', methods=['POST'])
@csrf.exempt
def delete_list():
    list_id = request.form.get("list_id", type=int)
    todo_list = get_user_list(list_id)
    if todo_list:
        db.session.delete(todo_list)
        db.session.commit()

    owner_id, session_id = get_current_owner()
    latest_list = (TodoList.query.filter_by(owner_id=owner_id).order_by(TodoList.id.desc()).first()
                   if owner_id
                   else TodoList.query.filter_by(session_id=session_id).order_by(TodoList.id.desc()).first())
    return redirect(url_for("index", list_id=latest_list.id if latest_list else None))


@app.route('/new-list', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def new_list():
    if request.method == 'POST':
        list_name = request.form.get('list_name') or "My to-do list"
        new_list = TodoList(title=list_name, owner=current_user)
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for("index", list_id=new_list.id))

    return render_template("new_list.html")


# ------------ Task Actions ------------

@app.route('/submit-task', methods=['POST'])
@csrf.exempt
def submit_task():
    list_id = request.form.get("list_id", type=int)
    task_title = request.form.get("task")

    todo_list = create_or_update_list(list_id)

    if task_title:
        new_task = Task(title=task_title, todo_list=todo_list)
        db.session.add(new_task)
        db.session.commit()

    return redirect(url_for("index", list_id=todo_list.id))


@app.route('/task/<int:task_id>/delete', methods=['POST'])
@csrf.exempt
def delete_task(task_id):
    task = get_task_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("index", list_id=task.todo_list_id))


@app.route('/task/<int:task_id>/toggle', methods=['POST'])
@csrf.exempt
def toggle_task(task_id):
    task = get_task_or_404(task_id)
    task.is_done = not task.is_done
    db.session.commit()
    return redirect(url_for("index", list_id=task.todo_list_id))


@app.route('/task/<int:task_id>/edit', methods=['POST'])
@csrf.exempt
def edit_task(task_id):
    task = get_task_or_404(task_id)
    task.title = request.form.get("title")
    date_str = request.form.get("date")
    try:
        task.date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        task.date = None
    task.is_done = "is_done" in request.form
    db.session.commit()
    return redirect(url_for("index", list_id=task.todo_list_id))


# -------------------- User Authentication --------------------

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


@app.post('/login-form')
@csrf.exempt
@limiter.limit("5 per 15 minutes")
def login_form():
    email = request.form.get('login-email', '').strip().lower()
    password_input = request.form.get('login-password', '')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password_input):
        guest_id = session.get("guest_id")
        session.clear()
        login_user(user, fresh=True)

        # Merge guest lists
        if guest_id:
            guest_lists = TodoList.query.filter_by(session_id=guest_id).all()
            for l in guest_lists:
                l.owner_id = user.id
                l.session_id = None
            db.session.commit()
        return redirect(url_for('index'))

    flash("Invalid credentials.", "error")
    return redirect(url_for('index'))


@app.route('/register-form', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per 15 minutes")
def register_form():
    email = request.form.get('register-email', '').strip().lower()
    password_input = request.form.get('register-password')

    if not is_strong_password(password_input):
        flash("Password too weak. Must be 8+ chars with uppercase, lowercase and number", "error")
        return redirect(url_for('index'))

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash("We couldn't complete the registration. Try a different email.", "error")
        return redirect(url_for('index'))
    hashed_password = generate_password_hash(password_input, method='pbkdf2:sha256', salt_length=16)
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    flash("Successfull user registration.", "success")
    return redirect(url_for('index'))


@app.post('/logout')
@login_required
@csrf.exempt
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))


# -------------------- Run App --------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
