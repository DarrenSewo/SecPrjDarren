from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root3'
app.config['MYSQL_PASSWORD'] = 'DarrenDBMS2024'
app.config['MYSQL_DB'] = 'pythonlogin2'
app.config['MYSQL_PORT'] = 3306

mysql = MySQL(app)
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return redirect(url_for('secure_login'))

# Vulnerable SELECT
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    msg = ''
    data = []
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # This query is vulnerable to SQL injection
        query = f"SELECT * FROM accounts WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        accounts = cursor.fetchall()

        if accounts:
            # Display all returned account details
            msg = 'Vulnerable login successful! Retrieved data:'
            data = accounts  # Capture the retrieved data
        else:
            msg = 'Incorrect username/password!'
    return render_template('vulnerable_login.html', msg=msg, data=data)

# Secure login
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Check if the user is blocked
        cursor.execute('SELECT * FROM login_attempts WHERE username = %s', (username,))
        login_attempt = cursor.fetchone()

        if login_attempt:
            if login_attempt['attempts'] >= 5:
                # Check if the block period has passed
                last_attempt = login_attempt['last_attempt']
                block_until = last_attempt + timedelta(minutes=5)
                if datetime.now() < block_until:
                    msg = 'Too many failed attempts. Try again later.'
                    return render_template('secure_login.html', msg=msg)
                else:
                    # Reset the failed attempts after the block period
                    cursor.execute('UPDATE login_attempts SET attempts = 0 WHERE username = %s', (username,))
                    mysql.connection.commit()

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and bcrypt.check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Reset failed attempts on successful login
            cursor.execute('DELETE FROM login_attempts WHERE username = %s', (username,))
            mysql.connection.commit()
            return 'Secure login successful!'
        else:
            # Increment failed attempts
            if login_attempt:
                cursor.execute(
                    'UPDATE login_attempts SET attempts = attempts + 1, last_attempt = %s WHERE username = %s',
                    (datetime.now(), username))
            else:
                cursor.execute('INSERT INTO login_attempts (username, attempts, last_attempt) VALUES (%s, 1, %s)',
                               (username, datetime.now()))
            mysql.connection.commit()
            msg = 'Incorrect username/password!'
    return render_template('secure_login.html', msg=msg)

@app.route('/MyWebApp/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('secure_login'))

@app.route('/MyWebApp/registration', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email'].encode()
        hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')
        key = Fernet.generate_key()
        with open("symmetric.key", "wb") as fo:
            fo.write(key)
        f = Fernet(key)
        encrypted_email = f.encrypt(email)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)', (username, hashpwd, encrypted_email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('registration.html', msg=msg)

@app.route('/MyWebApp/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('secure_login'))

@app.route('/MyWebApp/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        encrypted_email = account['email'].encode()
        with open('symmetric.key', 'rb') as file:
            key = file.read()
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email).decode()
        account['email'] = decrypted_email
        return render_template('profile.html', account=account)
    return redirect(url_for('secure_login'))

# Vulnerable update
@app.route('/vulnerable_update', methods=['POST', 'GET'])
def vulnerable_update():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Perform SQL injection vulnerable update
        query = f"UPDATE accounts SET password = '{new_password}' WHERE username = '{username}'"
        cursor.execute(query)
        mysql.connection.commit()

        # Check if the update was successful
        cursor.execute(f"SELECT * FROM accounts WHERE username = '{username}'")
        updated_account = cursor.fetchone()

        if updated_account:
            return f"Update successful! Updated account: {updated_account}"
        else:
            return "Update failed or account not found."

    return render_template('vulnerable_update.html')

# Vulnerable delete
@app.route('/vulnerable_delete', methods=['GET', 'POST'])
def vulnerable_delete():
    msg = ''
    if request.method == 'POST' and 'id' in request.form:
        user_id = request.form['id']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Vulnerable query allowing SQL injection
        query = f"DELETE FROM accounts WHERE id = '{user_id}'"
        cursor.execute(query)
        mysql.connection.commit()
        msg = 'Account deleted successfully (via SQL injection)!'

    return render_template('vulnerable_delete.html', msg=msg)

# Vulnerable insert
@app.route('/vulnerable_insert', methods=['GET', 'POST'])
def vulnerable_insert():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Vulnerable query allowing SQL injection
        query = f"INSERT INTO accounts (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        cursor.execute(query)
        mysql.connection.commit()
        msg = 'Account inserted successfully (via SQL injection)!'

    return render_template('vulnerable_insert.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)
