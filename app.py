from flask import Flask, render_template, request, flash, jsonify, session, redirect, url_for
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import re
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message


app = Flask(__name__, static_url_path='/static')
mail = Mail(app)
app.config['SECRET_KEY'] = "Rutuja@9049"


# SQLAlchemy Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/delegate_tracker_database'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


app.config['SESSION_TYPE'] = 'filesystem'  
app.config['SESSION_PERMANENT'] = False
Session(app)

# Configure Flask-Mail settings
app.config['MAIL_SERVER'] = 'smtp.example.com'  # SMTP server address
app.config['MAIL_PORT'] = 587  # Port for SMTP (587 for TLS)
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Your email username
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Your email password
app.config['MAIL_USE_TLS'] = True  # Enable TLS

# Initialize Flask-Mail
mail = Mail(app)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    delegate_email = db.Column(db.String(120), unique=True, nullable=False)
    delegate_passcode = db.Column(db.String(60), nullable=False)
    delegate_name = db.Column(db.String(100), nullable=False)
    delegate_address = db.Column(db.String(255), nullable=False)
    delegate_country = db.Column(db.String(100), nullable=False)
    delegate_city = db.Column(db.String(100), nullable=False)
    delegate_state = db.Column(db.String(100), nullable=False)
    delegate_zip = db.Column(db.String(20), nullable=False)
    
    
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref=db.backref('reset_token', uselist=False))



@app.route('/')
def home():
    return render_template('layout.html')

@app.route('/registration_page')
def registration_page():
    return render_template('registration_page.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

# Registration route
@app.route('/register', methods=['POST'])
def register():
    try:
        if request.method == 'POST':
            delegate_email = request.form.get('delegate_email')
            delegate_passcode = request.form.get('delegate_passcode')
            delegate_name = request.form.get('delegate_name')
            delegate_address = request.form.get('delegate_address')
            delegate_country = request.form.get('delegate_country')
            delegate_city = request.form.get('delegate_city')
            delegate_state = request.form.get('delegate_state')
            delegate_zip = request.form.get('delegate_zip')
            
            
            if not validate_password(delegate_passcode):
                response_data = {'success': False, 'message': 'Password must contain at least 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special symbol.'}
                return jsonify(response_data), 400  # Return 400 status code for bad request

           

            new_user = User(delegate_email=delegate_email, delegate_passcode=delegate_passcode,
                            delegate_name=delegate_name, delegate_address=delegate_address,
                            delegate_country=delegate_country, delegate_city=delegate_city,
                            delegate_state=delegate_state, delegate_zip=delegate_zip)

            db.session.add(new_user)
            db.session.commit()

            response_data = {
                'success': True,
                'message': 'Registration successful',
                'user_id': new_user.id,
                'delegate_email': new_user.delegate_email,
                'delegate_name': new_user.delegate_name,
                'delegate_country': new_user.delegate_country,
                'delegate_city': new_user.delegate_city,
                'delegate_state': new_user.delegate_state,
                'delegate_zip': new_user.delegate_zip,
            }

            print(request.form)
            print(response_data)
            print("hello")
            return jsonify(response_data)
        
        return redirect(url_for('login_page'))

    except Exception as e:
        print(f"Error: {e}")
        response_data = {'message': f'An error occurred during registration: {str(e)}', 'status': 'error'}
        return jsonify(response_data)
    

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        delegate_email = request.form.get('delegate_email')
        delegate_passcode = request.form.get('delegate_passcode')

        user = User.query.filter_by(delegate_email=delegate_email).first()

        if user :
            if user.delegate_passcode == delegate_passcode:
                session['user_id'] = user.id
                flash('Logged in successfully!', 'success')
                return redirect(url_for('user_home'))
            else:
                flash('Invalid passcode!', 'error')
        else:
            if delegate_passcode:  # Both email and passcode are wrong
                flash('Invalid delegate email and passcode!', 'error')
            else:
                flash('Invalid delegate email!', 'error')

        # Redirect back to login page if login fails
        return redirect(url_for('login_page'))

    return render_template('login.html')
    
    
# Password validation function
def validate_password(password):
    # Define regular expressions for each password requirement
    has_uppercase = re.search(r"[A-Z]", password)
    has_lowercase = re.search(r"[a-z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[!@#$%^&*()-_=+{};:,<.>]", password)
    is_valid_length = len(password) >= 8  # At least 8 characters long

    # Check if all requirements are met
    if has_uppercase and has_lowercase and has_digit and has_special and is_valid_length:
        return True
    else:
        return False
    
    
# Password reset request route
@app.route('/password_reset_request', methods=['GET', 'POST'])
def password_reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(delegate_email=email).first()
        if user:
            token = secrets.token_urlsafe(16)
            expires_at = datetime.now() + timedelta(hours=1)  # Token expires in 1 hour
            reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
            db.session.add(reset_token)
            db.session.commit()
            
            # Send password reset email with link containing token
            send_password_reset_email(user, token)

            flash('Password reset email sent!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User with that email address does not exist.', 'error')
    return render_template('password_reset_request.html')

# Function to send password reset email
def send_password_reset_email(user, token):
    reset_link = url_for('password_reset', token=token, _external=True)
    subject = 'Password Reset Request'
    body = f'Hello {user.delegate_name},\n\nYou requested a password reset. Click the following link to reset your password:\n{reset_link}'
    msg = Message(subject, recipients=[user.delegate_email], body=body)
    mail.send(msg)

    


# Route for handling password reset with token
@app.route('/password_reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if reset_token and reset_token.expires_at > datetime.now():
        if request.method == 'POST':
            user = User.query.get(reset_token.user_id)
            user.password = request.form['password']
            db.session.delete(reset_token)
            db.session.commit()
            flash('Password reset successful!', 'success')
            return redirect(url_for('login'))
        return render_template('password_reset.html', token=token)
    else:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))

    
    

@app.route('/update/<int:user_id>', methods=['GET', 'POST'])
def update(user_id):
    try:
        user = User.query.get(user_id)
        if request.method == 'POST':
            # Update user details based on form data
            user.delegate_email = request.form.get('delegate_email')
            user.delegate_passcode = request.form.get('delegate_passcode')
            user.delegate_name = request.form.get('delegate_name')
            user.delegate_address = request.form.get('delegate_address')
            user.delegate_country = request.form.get('delegate_country')
            user.delegate_city = request.form.get('delegate_city')
            user.delegate_state = request.form.get('delegate_state')
            user.delegate_zip = request.form.get('delegate_zip')

            db.session.commit()
            flash("User data updated successfully")
            return redirect(url_for('user_home'))
        return render_template('update.html', user=user)
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': f'An error occurred: {str(e)}', 'status': 'error'})

@app.route('/delete/<int:user_id>', methods=['POST'])
def delete(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'})
    except Exception as e:
        print(f"Error: {e}")
        response_data = {'message': f'An error occurred: {str(e)}', 'status': 'error'}
        return jsonify(response_data)

        
@app.route('/home')
def user_home():
    if 'user_id' in session:
        # Retrieve all users from the database
        users = User.query.all()
        return render_template('home.html', users=users)
    else:
        return redirect(url_for('login_page'))
    

# Logout route
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login_page'))
    #return jsonify({'success': True, 'message': 'Logout successful'})

if __name__ == '__main__':
    app.run(debug=True)



