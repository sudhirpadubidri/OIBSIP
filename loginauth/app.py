from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key in a real-world application

# In-memory storage for users (replace with a database in a real-world scenario)
users = {}

@app.route('/')
def home():
    if 'username' in session:
        return f'Hello, {session["username"]}! <a href="/logout">Logout</a>'
    return 'You are not logged in. <a href="/login">Login</a> or <a href="/register">Register</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return 'Username already exists. <a href="/register">Try again</a>'
        hashed_password = generate_password_hash(password, method='sha256')
        users[username] = hashed_password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return 'Invalid login credentials. <a href="/login">Try again</a>'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/secured')
def secured():
    if 'username' in session:
        return f'This is a secured page, {session["username"]}! <a href="/logout">Logout</a>'
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
