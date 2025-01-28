from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import Forbidden
import csv
import os
from models import db, Password, InputControl, User
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Custom password validation function
def validate_password(password):
    pattern = r'(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>])(?=.*[0-9])(?=.*[a-z]).{8,}'
    if not re.match(pattern, password):
        raise ValueError(
            'Password must contain at least one uppercase letter, one special character, '
            'one number, one lowercase letter, and be at least 8 characters long.'
        )

# Middleware to protect routes
def login_required(f):
    """Decorator to restrict access to authenticated users."""
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Admin login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check admin credentials
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['admin_logged_in'] = True
            return redirect(url_for('view_passwords'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('login'))

# Route for the password input form
@app.route('/', methods=['GET', 'POST'])
def index():
    save_flag = False
    error_message = ''

    control = InputControl.query.first()
    if control and not control.accepting_inputs:
        raise Forbidden("Form is currently disabled.")

    if request.method == "POST":
        password_input = request.form.get('password', '')

        try:
            validate_password(password_input)
            new_password = Password(password=password_input)
            db.session.add(new_password)
            db.session.commit()
            save_flag = True

        except ValueError as e:
            error_message = str(e)

    return render_template('index.html', save_flag=save_flag, error_message=error_message)

# Route to toggle form inputs
@app.route('/toggle_form', methods=['POST'])
@login_required
def toggle_form():
    control = InputControl.query.first()
    if not control:
        control = InputControl(accepting_inputs=True)
        db.session.add(control)

    control.accepting_inputs = not control.accepting_inputs
    db.session.commit()
    return redirect(url_for('view_passwords'))

# Route to display stored passwords
@app.route('/view')
@login_required
def view_passwords():
    passwords = Password.query.all()
    control = InputControl.query.first()
    accepting_inputs = control.accepting_inputs if control else True
    return render_template('view_passwords.html', passwords=passwords, accepting_inputs=accepting_inputs)

# Route to delete a password
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_password(id):
    password = Password.query.get_or_404(id)
    db.session.delete(password)
    db.session.commit()
    return redirect(url_for('view_passwords'))

# Route to download passwords as CSV
@app.route('/download')
@login_required
def download_csv():
    passwords = Password.query.all()
    filename = 'passwords.csv'
    file_path = os.path.join('static', filename)

    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['#', 'Passwords'])
        for idx, entry in enumerate(passwords, start=1):
            writer.writerow([idx, entry.password])

    return send_file(file_path, as_attachment=True)

@app.before_first_request
def create_tables():
    db.create_all()

    # Create the default admin user if it doesn't exist
    if not User.query.filter_by(username="admin").first():
        hashed_password = generate_password_hash("admin@000", method='sha256')
        admin_user = User(username="admin", password=hashed_password)
        db.session.add(admin_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
