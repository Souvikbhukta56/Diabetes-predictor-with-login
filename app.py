from flask import Flask, render_template,  request, redirect, url_for, flash

from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property
from flask_bcrypt import Bcrypt
from datetime import datetime
from forms import RegisterForm, LoginForm



from sklearn.linear_model import LogisticRegression
from pandas import read_csv

data1 = read_csv("flask-email-confirmation-reset/static/diabetes_data.csv")
model1 = LogisticRegression(max_iter=10000)
model1.fit(data1.drop(columns=['Outcome']), data1['Outcome'])



app  = Flask(__name__)

app.config['SECRET_KEY'] = 'hardsecretkey'

#SqlAlchemy Database Configuration With Mysql
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://anywhere25:souvik25@anywhere25.mysql.pythonanywhere-services.com/anywhere25$mylogin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Email related Configuration values
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'testingsouvik123@gmail.com'
app.config['MAIL_PASSWORD'] = 'testing@1234'



db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column(db.String(60), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    email_confirmation_sent_on = db.Column(db.DateTime, nullable=True)
    email_confirmed = db.Column(db.Boolean, nullable=True, default=False)
    email_confirmed_on = db.Column(db.DateTime, nullable=True)

    def __init__(self, email,username, plaintext_password, email_confirmation_sent_on=None):
        self.email = email
        self.username = username
        self._password = plaintext_password

        self.authenticated = False
        self.email_confirmation_sent_on = email_confirmation_sent_on
        self.email_confirmed = False
        self.email_confirmed_on = None

    @hybrid_property
    def password(self):
        return self._password

    @hybrid_method
    def verify_original_pass(self, plaintext_password):
        return bcrypt.check_password_hash(self._password, plaintext_password)

    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    @property
    def is_active(self):
        """Always True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        """Requires use of Python 3"""
        return str(self.id)




def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'info')



@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()


################
#### routes ####
################
@app.route('/')
def home():

    form = LoginForm(request.form)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
            try:
                email = form.email.data
                username = form.username.data
                password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

                confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
                confirm_url = url_for(
                    'confirm_email',
                    token=confirm_serializer.dumps(email, salt='email-confirmation-salt'),
                    _external=True)

                html = render_template(
                    'email_confirmation.html',
                    confirm_url=confirm_url)
                msg = Message('Hello', sender = 'testingsouvik123@gmail.com', recipients = [email])
                msg.html=html
                mail.send(msg)


                flash("Thanks for registering!  Please check your email to confirm your email address. (In case you can't find our email check your spam folder)", 'success')
                new_user = User(email, username, password)
                new_user.authenticated = True
                db.session.add(new_user)
                db.session.commit()


                return redirect(url_for('login'))

            except IntegrityError:
                db.session.rollback()
                flash('ERROR! Email ({}) already exists.'.format(form.email.data), 'error')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('ERROR! Incorrect login credentials.', 'error')
        elif user.email_confirmed==0:
            flash('Your acount is not activated! Please open your email inbox and click activation link we sent to activate it', 'info')
        elif user is not None and user.verify_original_pass(form.password.data):
            user.authenticated = True
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('You are logged in now, {}'.format(current_user.username))
            return redirect(url_for('blog'))

    return render_template('login.html', form=form)


# email confirmation and activationm route functions
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=86400)
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Thank you for confirming your email address!', 'success')

    return redirect(url_for('blog'))

@app.route('/blog', methods=['POST', 'GET'])
@login_required
def blog():
    prognosis = ''
    if(request.method=='POST'):
        preg = float(request.form.get('Pregnancies'))
        glu = float(request.form.get('Glucose'))
        bp = float(request.form.get('BloodPressure'))
        ins = float(request.form.get('Insulin'))
        bmi = float(request.form.get('BMI'))
        age = float(request.form.get('Age'))
        prognosis = model1.predict([[preg, glu, bp, ins, bmi, age]])

    return render_template('blog.html', prog=prognosis)


@app.route('/logout')
@login_required
def logout():
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    flash('You are logged out,we hope you come back soon!', 'info')
    return redirect(url_for('login'))




#run flask app
if __name__ == "__main__":
    app.run(debug=True)