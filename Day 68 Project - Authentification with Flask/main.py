from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    # For some reason, using db.session.execute returns attribute error.
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        existing_user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()

        if existing_user is None:
            hashed_password = generate_password_hash(request.form.get("password"),
                                                     method="pbkdf2:sha256", salt_length=8)
            new_user = User(email=request.form.get("email"),
                            password=hashed_password,
                            name=request.form.get("name"))
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('secrets'))
        else:
            flash("This email has already been registered. Log in instead!")
            return redirect(url_for('login'))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        if user is None:
            flash("This email has not yet been registered.")
            return render_template("login.html")
        else:
            if check_password_hash(user.password, request.form.get("password")) is True:
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash("Password does not match.")
                return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    # Current user is saved
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!')
    return render_template("login.html")


@app.route('/download')
@login_required
def download():
    return send_from_directory("./", "./static/files/cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run()
