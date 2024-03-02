from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
import random
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Submit')

    def validate_otp(self, field):
        if field.data != session.get('otp_code'):
            raise ValidationError('Invalid OTP code')

@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = LoginForm()
    otp_form = OTPForm()
    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data
        if username == '1' and password == '1':
            return redirect(url_for('generate_qr'))
        else:
            return "Invalid credentials! Please try again."
    return render_template('login.html', login_form=login_form, otp_form=None)

@app.route('/generate_qr', methods=['GET', 'POST'])
def generate_qr():
    if 'otp_code' not in session:
        qr_code = str(random.randint(100000, 999999))  # 9-digit OTP
        session['otp_code'] = qr_code  # Save OTP code in session
    else:
        qr_code = session['otp_code']

    qr = qrcode.make(qr_code)
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    img_data = img_io.getvalue()
    img_src = 'data:image/png;base64,' + base64.b64encode(img_data).decode()

    otp_form = OTPForm()

    if request.method == 'POST' and otp_form.validate_on_submit():
        if otp_form.otp.data == session.get('otp_code'):
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
    app.run(debug=True)