from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import logout_user, login_user, login_required, UserMixin, current_user, LoginManager

app = Flask(__name__)
app.secret_key = "Helloworld"

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/python'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False

db = SQLAlchemy(app)

# ------------------- Model -------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(20), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(150))
    Created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    Tasks = db.relationship('Task', backref='user', passive_deletes=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Judul = db.Column(db.VARCHAR(150), nullable=False)
    Deskripsi = db.Column(db.TEXT(450), nullable=False)
    Created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
    def __init__(self, Judul, Deskripsi, author):
        self.Judul = Judul
        self.Deskripsi = Deskripsi
        self.author = author


# ------------------- Home Route -------------------------

@app.route('/')
@login_required
def index():
    tugas = Task.query.all()
    return render_template("index.html", tugas=tugas, user=current_user)

@app.route('/create', methods = ['GET', 'POST'])
@login_required
def create():
    
    if request.method == 'POST':
        Judul = request.form['Judul']
        Deskripsi = request.form['Deskripsi']

        tugas = Task(Judul, Deskripsi, author=current_user.id)
        db.session.add(tugas)
        db.session.commit()
        flash('Data berhasil ditambahkan')
        return redirect(url_for('index'))

    else:
        return render_template("create.html", user=current_user)

@app.route('/delete/<int:id>', methods = ['GET', 'POST'])
def delete(id):
    tugas = Task.query.get(id)
    db.session.delete(tugas)
    db.session.commit()
    return redirect('/')

# ------------------- Auth Route -------------------------

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash('Password is incorrect.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('Email is already in use.', category='error')
        elif username_exists:
            flash('Username is already in use.', category='error')
        elif password1 != password2:
            flash('Password don\'t match!', category='error')
        elif len(username) < 2: 
            flash('Username is too short.', category='error')
        elif len(password1) < 6:
            flash('Password is too short.', category='error')
        elif len(email) < 4:
            flash("Email is invalid.", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('User created!')
            return redirect(url_for('index'))

    return render_template("signup.html", user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ------------------- login Manager -------------------------

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

if  __name__ == "__main__":
    app.run(debug=True, port=8080)