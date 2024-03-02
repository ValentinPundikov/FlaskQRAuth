from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
import random
import qrcode
from io import BytesIO
import base64
import sqlite3

# Функция для создания базы данных, если она не существует
def create_database():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, code INTEGER, susername TEXT, spassword TEXT)''')
    conn.commit()
    conn.close()

# Функция для создания нового пользователя
def create_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # Возникает, если пользователь с таким именем уже существует
        conn.close()
        return False

# Функция для проверки существования пользователя
def user_exists(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[1]  # Возвращаем только логин
    else:
        return None  # Возвращаем None, если пользователя не существует

# Функция для проверки пароля у существующего пользователя
def check_password(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0]  # Возвращаем только пароль
    else:
        return None  # Возвращаем None, если пользователя не существует



def create_multiple_users():
    users = [
        ("user1", "password1"),
        ("user2", "password2"),
        ("user3", "password3"),
        ("user4", "password4"),
        ("user5", "password5"),
        ("user6", "password6")
    ]
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    for username, password in users:
        # Проверяем, существует ли пользователь с таким именем
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        existing_user = c.fetchone()
        if not existing_user:
            # Если пользователь не существует, добавляем его в базу данных
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def add_code(username, password, code):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET code=? WHERE username=? AND password=?", (code, username, password))
    conn.commit()
    conn.close()





def get_code(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT code FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return str(result[0])  # Преобразуем код в строку
    else:
        return None

# Функция для удаления кода у пользователя
def delete_code(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET code=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Submit')

    # def validate_otp(self, field):
    #     if field.data != session.get('otp_code'):
    #         raise ValidationError('Invalid OTP code')

@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = LoginForm()
    otp_form = OTPForm()
    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data
        print(username)
        print(password)
        existing_username = user_exists(username)  # Получаем логин пользователя из базы данных
        existing_password = check_password(username)  # Получаем пароль пользователя из базы данных
        if existing_username and password == existing_password:  # Проверяем введенные данные
            return redirect(url_for('generate_qr', username=username, password=password))
        else:
            return "Invalid credentials! Please try again."
    return render_template('login.html', login_form=login_form, otp_form=None)

@app.route('/generate_qr', methods=['GET', 'POST'])
def generate_qr():
    if request.method == 'GET':
        username = request.args.get('username')
        password = request.args.get('password')
        session['username'] = username
        session['password'] = password
        qr_code = random.randint(100000, 999999)  # 6-digit OTP
        session['otp'] = qr_code  # Сохраняем код в сессии
        add_code(username, password, qr_code)  # Добавляем код в базу данных
    else:
        username = session.get('username')
        password = session.get('password')

    qr_code = session.get('otp')  # Используем сохраненный код из сессии

    qr = qrcode.make(str(qr_code))
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    img_data = img_io.getvalue()
    img_src = 'data:image/png;base64,' + base64.b64encode(img_data).decode()

    otp_form = OTPForm()

    if request.method == 'POST' and otp_form.validate_on_submit():
        if otp_form.otp.data == str(qr_code):
            delete_code(username)
            return redirect(url_for('success'))  # Redirect to success page
        else:
            return redirect(url_for('error'))    # Redirect to error page

    return render_template('qr.html', img_src=img_src, otp_form=otp_form)

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/error')
def error():
    return render_template('error.html')

if __name__ == '__main__':
    create_database()
    create_multiple_users()
    app.run(debug=True)