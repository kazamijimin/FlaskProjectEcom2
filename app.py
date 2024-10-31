from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import mysql.connector
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from smtplib import SMTPException
import random
import smtplib
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
import re
from flask_socketio import SocketIO, emit


app = Flask(__name__)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.secret_key = 'brunomars'  # Change this to a more secure key in production
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mendozanicknarry@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'a'
app.config['MAIL_DEFAULT_SENDER'] = 'mendozanicknarry@gmail.com'  # Your email
# Configure Google Login
google_bp = make_google_blueprint(
    client_id="a",
    client_secret="a",
    scope=["https://www.googleapis.com/auth/userinfo.profile", 
           "https://www.googleapis.com/auth/userinfo.email", 
           "openid"],    
    redirect_to="google_login"
    
)
app.register_blueprint(google_bp, url_prefix="/login")

# Configure Facebook Login
facebook_bp = make_facebook_blueprint(
    client_id="a",
    client_secret="a",
    
    redirect_to="facebook_login"

)
app.register_blueprint(facebook_bp, url_prefix="/login")

mail = Mail(app)
# messages = []

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth_page'  # Set the login view

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="data"
        )
        return conn
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_all_products_with_categories():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT p.*, c.category_name
        FROM product p
        JOIN category c ON p.category_id = c.id
        ORDER BY c.category_name, p.product_name
    '''
    cursor.execute(query)
    products = cursor.fetchall()
    cursor.close()
    connection.close()
    return products         
# Google login route
@app.route("/google_login")
def google_login():
    conn = get_db_connection()
    if not google.authorized:
        return redirect(url_for("google.login"))

    response = google.get("/oauth2/v1/userinfo")
    if not response.ok:
        return "Could not fetch user information from Google.", 400

    user_info = response.json()
    email = user_info.get("email")
    name = user_info.get("name", "User")
    google_id = user_info.get("id")

    if not email:
        return "Error: Email not provided by Google.", 400

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        # If user exists, log them in
        session["user_id"] = existing_user["id"]
        session["first_name"] = existing_user["first_name"]
        session["google_login"] = True  # Mark as Google login user
        login_user(User.get_by_id(existing_user["id"]))  # Login with Flask-Login
        flash(f"Welcome back, {existing_user['first_name']}!", "success")
    else:
        try:
            # Create a new user if not found
            cursor.execute(
                "INSERT INTO users (first_name, email, google_id, verified) VALUES (%s, %s, %s, %s)",
                (name, email, google_id, True)  # Verified by Google
            )
            conn.commit()
            user_id = cursor.lastrowid
            session["user_id"] = user_id
            session["first_name"] = name
            session["google_login"] = True  # Mark as Google login user
            login_user(User.get_by_id(user_id))  # Login with Flask-Login
            flash(f"Hello, {name}! You have been registered and logged in with Google.", "success")
        except mysql.connector.Error as err:
            conn.rollback()
            print("Database Error:", err)
            return "Failed to store user in database.", 500

    cursor.close()
    return redirect(url_for("home"))

# Facebook login route
@app.route("/facebook_login")
def facebook_login():
    conn = get_db_connection()
    
    # Check if authorized by Facebook OAuth
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))

    # Attempt to get user info from Facebook
    response = facebook.get("/me?fields=id,name,email")
    if not response.ok:
        return "Could not fetch user information from Facebook.", 400

    try:
        user_info = response.json()
        email = user_info.get("email")
        name = user_info.get("name", "User")
        facebook_id = user_info.get("id")
    except ValueError:
        return "Error: Facebook did not return JSON data.", 400

    # Ensure email exists
    if not email:
        return "Error: Email not provided by Facebook.", 400

    # Check if the user exists in the database
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        # Log in existing user
        session["user_id"] = existing_user["id"]
        session["first_name"] = existing_user["first_name"]
        session["login_source"] = "Facebook"
        
        # Call login_user for Flask-Login integration
        login_user(User.get_by_id(existing_user["id"]))  # Assumes `User.get_by_id` method exists
        
        flash(f"Welcome back, {existing_user['first_name']}! Logged in with Facebook.", "success")
    else:
        # Register new user if not found
        try:
            cursor.execute(
                "INSERT INTO users (first_name, email, facebook_id, verified) VALUES (%s, %s, %s, %s)",
                (name, email, facebook_id, True)  # Verified by Facebook
            )
            conn.commit()
            user_id = cursor.lastrowid
            session["user_id"] = user_id
            session["first_name"] = name
            session["login_source"] = "Facebook"
            
            # Call login_user for new user
            login_user(User.get_by_id(user_id))  # Assumes `User.get_by_id` method exists
            
            flash(f"Hello, {name}! You have been registered and logged in with Facebook.", "success")
        except mysql.connector.Error as err:
            conn.rollback()
            print("Database Error:", err)
            return "Failed to store user in database.", 500

    cursor.close()
    return redirect(url_for("home"))

@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    admin_id = session.get('user_id')
    
    cursor = conn.cursor(dictionary=True)
    
    # Check if the user is admin
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (admin_id,))
    admin_result = cursor.fetchone()
    
    if not admin_result or not admin_result['is_admin']:
        flash("Unauthorized access. Admins only.", "danger")
        return redirect(url_for('home'))  # Redirect non-admins to the home page

    # Fetch users if admin check passes
    query = "SELECT * FROM users"
    cursor.execute(query)
    users = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('dashboard/index.html', users=users)
@app.route('/vendor_dashboard')
@login_required
def vendor_dashboard():
    user_id = current_user.id  # Assuming 'id' is the field in your user model
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Sales Data
    cursor.execute("""
        SELECT SUM(`order`.quantity) as total_units_sold, SUM(`order`.price * `order`.quantity) as total_revenue 
        FROM `order` 
        JOIN product ON `order`.product_link = product.id
        WHERE product.user_id = %s
    """, (user_id,))
    sales_data = cursor.fetchone()

    # Products Overview
    cursor.execute("""
        SELECT id, product_name, current_price, in_stock 
        FROM product 
        WHERE user_id = %s
    """, (user_id,))
    products = cursor.fetchall()

    # Orders Overview
    cursor.execute("""
        SELECT `order`.id, `order`.quantity, `order`.status, `order`.price,
               users.first_name as customer_name
        FROM `order`
        JOIN product ON `order`.product_link = product.id
        JOIN users ON `order`.customer_link = users.id
        WHERE product.user_id = %s
    """, (user_id,))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('vendors_dashboard.html', sales_data=sales_data, products=products, orders=orders, user=current_user)



@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception as e:
        current_app.logger.error(f"Error verifying token: {e}")
        return False
    return email

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the user exists
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user:
            try:
                token = generate_reset_token(email)
                reset_link = url_for('reset_password', token=token, _external=True)

                msg = Message('Password Reset Request', recipients=[email])
                msg.body =f"""Subject: Password Reset Request
Dear GameBox User,

We received a request to reset the password for your account associated with this email address. If you made this request, please click the link below to reset your password:

[Password Reset Link]

For your security, this link will expire in 30 minutes. If you did not request a password reset, you can safely ignore this email, and no changes will be made to your account.

If you need further assistance, feel free to contact our support team.

Best regards,
GameBox Support Team {reset_link}"""

                print(f"Attempting to send email to {email}...")  # Debug line
                mail.send(msg)
                flash('A password reset link has been sent to your email. Kindly check your spam or inbox', category='success')
                print(f"Email sent to {email} successfully!")  # Debug line
                
            except Exception as e:
                current_app.logger.error(f"Error sending email: {e}")
                flash("There was an error sending the email. Please try again later.", category='danger')
                print(f"SMTP error: {e}")  # Debugging SMTP errors

            return redirect(url_for('home'))  # Redirect to login instead of logout

        cursor.close()
        conn.close()

    return render_template('reset_password_request.html', user=current_user)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', category='info')
        return redirect(url_for('reset_password_request'))

    conn = None
    cursor = None
    try:
        if request.method == 'POST':
            new_password = request.form['password']

            # Establish a connection to the database
            conn = get_db_connection()
            cursor = conn.cursor()

            # Update the password in the database
            hashed_password = generate_password_hash(new_password)
            update_query = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(update_query, (hashed_password, email))

            # Commit the changes to the database
            conn.commit()

            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))

    except Exception as e:
        current_app.logger.error(f"Database error: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Pass the token to the template
    return render_template('reset_token.html', user=current_user, token=token)


from flask_dance.contrib.google import google

@app.route("/logout")
def logout():
    session.clear()
    logout_user()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("home"))

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        # Retrieve form data
        email = request.form.get('email')
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        bio = request.form.get('bio')

        # Check if profile_picture is in request files
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '' and allowed_file(file.filename):
                # Secure the filename and save the file to the UPLOAD_FOLDER
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    print(f"Profile picture saved successfully to {file_path}")
                    image_path = filename
                except Exception as e:
                    print(f"Error saving profile picture: {str(e)}")
                    image_path = current_user.image_path  # Use the current image if there's an error
            else:
                print("Invalid file or no file selected, using the current image path.")
                image_path = current_user.image_path  # Use the current image if the file is invalid
        else:
            print("No profile_picture in request.files, using the current image path.")
            image_path = current_user.image_path  # Fallback to current user's image path

        # Get the database connection
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                # Update user information in the database
                cursor.execute("""
                    UPDATE users SET email = %s, username = %s, first_name = %s, bio = %s, image_path = %s WHERE id = %s
                """, (email, username, first_name, bio, image_path, current_user.id))
                conn.commit()

                # Reflect changes in the current_user object for the current session
                current_user.email = email
                current_user.username = username
                current_user.first_name = first_name
                current_user.bio = bio
                current_user.image_path = image_path

                flash('Profile updated successfully!', category='success')
                print("Profile updated successfully in the database.")
            except mysql.connector.Error as e:
                conn.rollback()
                print(f"Database error: {str(e)}")
                flash(f'An error occurred: {str(e)}', category='error')
            finally:
                cursor.close()
                conn.close()

        return redirect(url_for('profile'))

    return render_template('update_profile.html', user=current_user)
@app.route('/featured_products')
def featured_products():
    # conn = get_db_connection()
    # cursor = conn.cursor()
    # cursor.execute("SELECT * FROM products WHERE featured = 1")
    # featured_products = cursor.fetchall()
    return render_template('featured_products.html', user=current_user)
@app.route('/profile')
@login_required
def profile():
    return render_template('viewprofile.html', user=current_user)
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password  = request.form.get('current_password')
        new_password =  request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', category='error')
            return render_template('change_pass.html', user=current_user)

        elif new_password != confirm_password:
            flash("New or Confirm password doesn't match", "error")
            return render_template('change_pass.html', user=current_user)

        elif len(new_password) < 7:
            flash('Password is too short', 'error')
        else:
            hash_password = generate_password_hash(new_password,  method='pbkdf2:sha256')
            
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(""" UPDATE users SET password = %s WHERE id = %s """, (hash_password, current_user.id))
                    conn.commit()
                    flash('Password updated successfully', category='success')
                    return redirect(url_for('profile'))
                except mysql.connector.Error as e:
                    conn.rollback()
                    flash(f'An error occurred: {str(e)}', category='error')
                finally:
                    cursor.close()
                    conn.close()
        return redirect(url_for('profile'))

    return render_template('change_pass.html', user=current_user)

@app.route('/', methods=['GET', 'POST'])
def home():
    search_query = request.args.get('query', '')  # Get the search query
    conn = get_db_connection()
    products_by_category = {}
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Modify query based on search input
        if search_query:
            cursor.execute('''
                SELECT p.*, c.NAME AS category_name
                FROM product p
                JOIN categories c ON p.category_id = c.id
                WHERE (p.product_name LIKE %s OR c.NAME LIKE %s) AND p.is_approved = %s
            ''', (f'%{search_query}%', f'%{search_query}%', True))
        else:
            cursor.execute('''
                SELECT p.*, c.NAME AS category_name
                FROM product p
                JOIN categories c ON p.category_id = c.id
                WHERE p.is_approved = %s
            ''', (True,))

        products = cursor.fetchall()

        # Group products by category
        for product in products:
            category = product['category_name']
            if category not in products_by_category:
                products_by_category[category] = []
            products_by_category[category].append(product)

        cursor.close()
        conn.close()

    profile_image = current_user.image_path if current_user.is_authenticated and current_user.image_path else 'default_profile.png'
    
    # Pass products_by_category to the template
    return render_template('home.html', user=current_user, profile_image=profile_image, products_by_category=products_by_category)


 # Ensure user is always passed
def send_email(recipient, body, subject):
    sender_email = "mendozanicknarry@gmail.com"
    password="hxkd lrjk dlra djzq"

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        message = f'Subject : {subject}\n{body}'
        server.sendmail(sender_email, recipient, message)
@app.route('/add_user', methods=['POST'])
def add_user():
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        username = request.form.get('username')
        password = request.form.get('password')
        date_joined = request.form.get('date_joined')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, first_name, username, password, date_joined) VALUES (%s, %s, %s, %s, %s)
                ''', (email, first_name,  username, hashed_password, date_joined))
            conn.commit()
            flash('User Added successfully!', category='success')
        except Exception as e:
            flash(f'Error adding user: {e}', category='error')
        finally:
            cursor.close()
        return redirect(url_for('dashboard'))
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Execute delete query
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash('User deleted successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error deleting user: ' + str(e), 'danger')
    finally:
        cursor.close()
        
    return redirect(url_for('dashboard'))

@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    email = request.form.get('email')
    first_name = request.form.get('first_name')
    username = request.form.get('username')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET first_name = %s, email = %s, username = %s WHERE id = %s
        """, (first_name, email, username, user_id))
        conn.commit()
        flash('Updated user successfully!', category='success')
    except Exception as e:
        flash(f'Error updating user: {e}', category='error')
    finally:
        cursor.close()
    return redirect(url_for('dashboard'))
            
@app.route('/login', methods=['GET', 'POST'])
def auth_page():
    if "facebook_login" in session:
        flash(f"Welcome, {session.get('first_name')}!", category='success')
        return redirect(url_for('home'))
    if "google_login" in session:
        # User is authenticated through Google
        flash(f"Welcome, {session.get('first_name')}!", category='success')
        return redirect(url_for("home"))
    if request.method == 'POST':
        if 'login' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')

            user = User.get_by_email(email)  # Fetch user by email
            if user:
                if check_password_hash(user.password, password):
                    if user.verified:  # Check if the user is verified
                        session['user_id'] = user.id
                        login_user(user, remember=True)

                        flash('Logged in successfully!', category='success')
                        return redirect(url_for('home'))  # Redirect to home
                    else:
                        flash('Your account is not verified. Please check your email for the OTP.', category='error')
                else:
                    flash('Invalid email or password.', category='error')
            else:
                flash('No user found with this email.', category='error')
            

        elif 'sign_up' in request.form:
            email = request.form.get('email')
            first_name = request.form.get('firstName')
            username = request.form.get('username')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')
            
            
            existing_user = User.get_by_email(email)
            
            if existing_user:
                flash('Email already exists', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 4 characters', category='error')
            elif len(first_name) < 2:
                flash('First Name must be greater than 2 characters', category='error')
            elif password1 != password2:
                flash('Passwords do not match', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters', category='error')
            elif " " in password1:
                flash('Password cannot contain spaces', category='error')
            

            else:
                hashed_password = generate_password_hash(password1, method='pbkdf2:sha256')

                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    # Insert the user without OTP first, and set verified to False
                    cursor.execute(""" 
                        INSERT INTO users (email, username, first_name, password, date_joined, image_path, verified) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (email, username, first_name, hashed_password, datetime.now(), 'default.jpg', False))  # Set verified to False
                    connection.commit()

                    otp = str(random.randint(100000, 999999))
                    otp_expiration = datetime.now() + timedelta(minutes=10)
                    cursor.execute("""UPDATE users SET otp = %s, otp_expiration = %s WHERE email = %s """, (otp, otp_expiration, email))
                    connection.commit()
                    send_email(email, "Your OTP Code", f"Your OTP code is {otp}. It is valid for 10 minutes.")
                    flash('Account created! Please check your email for the OTP.', category='success')
                    return redirect(url_for('verify_otp', email=email))
                except Exception as e:
                    connection.rollback()
                    flash(f'An error occurred: {str(e)}', category='error')
                finally:
                    cursor.close()
                    connection.close()

    return render_template('register.html', user=current_user)

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if user['otp'] == entered_otp and datetime.now() < user['otp_expiration']:
                # OTP is valid, mark user as verified
                cursor.execute("UPDATE users SET otp = NULL, otp_expiration = NULL, verified = TRUE WHERE email = %s", (email,))
                connection.commit()
                flash('Your email has been verified! You can now log in.', category='success')
                return redirect(url_for('auth_page'))  # Redirect to login page
            else:
                flash('Invalid or expired OTP.', category='error')

        cursor.close()

    return render_template('verify_otp.html', email=email, user=current_user)
@app.route('/resend_otp/<email>', methods=['POST'])
def resend_otp(email):
    connection = get_db_connection()
    cursor = connection.cursor()

    # Generate new OTP and set expiration
    otp = str(random.randint(100000, 999999))
    otp_expiration = datetime.now() + timedelta(minutes=10)

    try:
        # Update the user's OTP and expiration in the database
        cursor.execute("""
            UPDATE users 
            SET otp = %s, otp_expiration = %s 
            WHERE email = %s
        """, (otp, otp_expiration, email))
        connection.commit()

        # Send the new OTP email
        send_email(email, "Your New OTP Code", f"Your new OTP code is {otp}. It is valid for 10 minutes.")

        flash('A new OTP has been sent to your email.', category='success')
    except Exception as e:
        connection.rollback()
        flash(f'An error occurred while resending OTP: {str(e)}', category='error')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('verify_otp', email=email))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Fetch all categories from the database
    cursor.execute("SELECT id, name FROM categories")
    categories = cursor.fetchall()  # Fetching the list of categories from the DB

    if request.method == 'POST':
        product_names = request.form.getlist('product_name[]')
        current_prices = request.form.getlist('current_price[]')
        previous_prices = request.form.getlist('previous_price[]')
        in_stocks = request.form.getlist('in_stock[]')
        flash_sales = request.form.getlist('flash_sale[]')  # This will only contain checked values
        date_addeds = request.form.getlist('date_added[]')
        descriptions = request.form.getlist('description[]')
        category_ids = request.form.getlist('category_id[]')

        # Handle multiple product pictures
        product_pictures = request.files.getlist('product_picture[]')

        # Use zip to safely iterate over multiple lists
        for i, (product_name, current_price, previous_price, in_stock, date_added, description, category_id) in enumerate(zip(product_names, current_prices, previous_prices, in_stocks, date_addeds, descriptions, category_ids)):
            # Check if flash_sale is checked
            flash_sale = flash_sales[i] if i < len(flash_sales) else 'no'  # Set default if not checked

            print(f"Adding product: {product_name}, Current Price: {current_price}, Previous Price: {previous_price}, In Stock: {in_stock}, Flash Sale: {flash_sale}, Date Added: {date_added}, Description: {description}, Category: {category_id}")

            # Handle product picture
            if product_pictures[i].filename != '' and allowed_file(product_pictures[i].filename):
                filename = secure_filename(product_pictures[i].filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    product_pictures[i].save(file_path)
                    product_picture = filename
                except Exception as e:
                    product_picture = 'default_product.png'
                    print(f"Error saving product picture: {e}")
            else:
                product_picture = 'default_product.png'

            # Insert into the database for each product
            Product.add_products(
                product_name,
                current_price,
                previous_price,
                in_stock,
                product_picture,
                flash_sale,
                date_added,
                description,
                current_user.id,
                category_id
            )

        flash('Pending products. Wait for approval', category='info')
        return redirect(url_for('products'))

    cursor.close()
    connection.close()

    return render_template('add_product.html', user=current_user, categories=categories)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    #para malaman kung ilan kasi bawal mag 0 pag quantity dapat default nya is 1
    quantity = int(request.form.get('quantity', 1))
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    query = "SELECT * FROM cart WHERE customer_link = %s AND product_link = %s"
    cursor.execute(query, (current_user.id, product_id))
    cart_item = cursor.fetchone()

    if cart_item:
        new_quantity = cart_item['quantity'] + quantity
        update_query = "UPDATE cart SET quantity = %s WHERE customer_link = %s AND product_link = %s"
        cursor.execute(update_query, (new_quantity, current_user.id, product_id))
    else:
        insert_query = "INSERT INTO cart (customer_link, product_link, quantity) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (current_user.id, product_id, quantity))
    connection.commit()

    cursor.close()
    flash('Product added to cart succesfully', category='success')
    return redirect(url_for('view_cart', user=current_user))
@app.route('/cart')
@login_required
def view_cart():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    query = """
    SELECT p.id, p.product_name, p.current_price, p.product_picture, c.quantity, (p.current_price * c.quantity) as total_price
    FROM product p
    JOIN cart c ON p.id = c.product_link
    WHERE customer_link = %s
    """

    cursor.execute(query, (current_user.id,))
    cart_items = cursor.fetchall()

    total_cost = sum(item['total_price'] for item in cart_items)

    return render_template('cart.html', cart_items=cart_items, total_cost=total_cost, user=current_user)
@app.route('/product/<int:product_id>', methods=['GET'])
def product_detail(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Query for product details including user email and profile picture
    cursor.execute('''
        SELECT p.*, u.email AS user_email, u.image_path AS user_image_path
        FROM product p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = %s
    ''', (product_id,))
    product = cursor.fetchone()


    # Query for product variants
    cursor.execute(''' 
        SELECT id, game_type, edition, platform, region, dlc_available, stock 
        FROM product_variants 
        WHERE product_id = %s
    ''', (product_id,))
    variants = cursor.fetchall()

    # Query for product reviews
    cursor.execute(''' 
        SELECT reviews.review_text, reviews.rating, reviews.created_at, users.email 
        FROM reviews 
        JOIN users ON reviews.user_id = users.id 
        WHERE reviews.product_id = %s
    ''', (product_id,))
    reviews = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('product_detail.html', user=current_user, product=product, variants=variants, reviews=reviews)


@app.route('/user/<int:user_id>', methods=['GET'])
def user_profile(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM  users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.execute("SELECT * FROM product WHERE  user_id = %s", (user_id,))
    products = cursor.fetchall()
  
    cursor.close()
    conn.close()
    return render_template("user_profile.html", user=user, products=products)


@app.route('/update_cart/<int:product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    quantity = int(request.form['quantity'])
    if quantity > 0:
        query = "UPDATE cart SET quantity = %s WHERE user_id = %s AND product_id = %s"
        cursor.execute(query, (quantity, current_user.id, product_id))
    else:
        query = "DELETE FROM cart WHERE user_id = %s AND product_id = %s"
        cursor.execute(query, (current_user.id, product_id))
    
    conn.commit()
    return redirect(url_for('view_cart'))
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    total_cost = 0
    conn = get_db_connection()

    if request.method == 'POST':
        # Handle Buy Now functionality
        product_id = request.form.get('product_id')
        quantity = request.form.get('quantity', 1)  # Default to 1 if not specified
        
        if product_id:  # If the product_id is provided, handle the Buy Now scenario
            product_id = int(product_id)

            # Fetch the product details for the selected product
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM product WHERE id = %s", (product_id,))
            product = cursor.fetchone()

            if product:
                # Calculate total cost
                total_cost = product['current_price'] * int(quantity)

                # Send confirmation email
                msg = Message("Order Confirmation",
                              sender="your_email@gmail.com",
                              recipients=[current_user.email])
                msg.body = f"Thank you for your order of {quantity} x {product['product_name']}! Your total is ${total_cost}."
                msg.html = render_template('email_confirmation.html', total_cost=total_cost, items=[product])
                mail.send(msg)

                # Insert the order into the database
                order_query = """
                INSERT INTO `order` (quantity, price, status, payment_id, customer_link, product_link) 
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                payment_id = "dummy_payment_id"  # Replace this with actual payment processing logic
                cursor.execute(order_query, (quantity, total_cost, 'Pending', payment_id, current_user.id, product_id))
                
                # Commit the transaction to save the order
                conn.commit()

                # Get the last inserted order ID for redirection
                order_id = cursor.lastrowid

                flash('Checkout successful! Your total is $' + str(total_cost), 'success')
                return redirect(url_for('order_details', order_id=order_id))

        # Handle cart-based checkout (if applicable)
        selected_products = request.form.getlist('selected_products')
        selected_product_ids = [int(product_id) for product_id in selected_products if product_id.isdigit()]

        if selected_product_ids:
            # Your existing code for handling cart checkout...
            pass

    # GET request handling remains unchanged
    cursor = conn.cursor(dictionary=True)

    fetch_cart_query = """
    SELECT p.id, p.product_name, p.current_price, p.product_picture, 
           SUM(c.quantity) as total_quantity, 
           (p.current_price * SUM(c.quantity)) as total_price
    FROM product p
    JOIN cart c ON p.id = c.product_link
    WHERE c.customer_link = %s
    GROUP BY p.id, p.product_name, p.current_price, p.product_picture
    """

    cursor.execute(fetch_cart_query, (current_user.id,))
    selected_cart_items = cursor.fetchall()

    total_cost = sum(item['total_price'] for item in selected_cart_items)
    cursor.close()

    return render_template('checkout.html', user=current_user, selected_cart_items=selected_cart_items, total_cost=total_cost)
@app.route('/wishlist/add/<int:product_id>', methods=['POST'])
def wishlist(product_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth_page'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM wishlist WHERE user_id = %s AND  product_id = %s",(user_id, product_id))
    wishlist_item = cursor.fetchone()

    if wishlist_item:
        flash("Product is already in your wishlist", category="info")
    else:
        cursor.execute("INSERT INTO wishlist (user_id, product_id) VALUES(%s, %s)",(user_id, product_id))
        conn.commit()
        flash("Product added to wishlist successfully", category="success")
    
    cursor.close()
    conn.close()
    return redirect(request.referrer or url_for('home'))
@app.route('/wishlist/remove/<int:product_id>', methods=['POST'])
def remove_wishlist(product_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth_page'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM wishlist WHERE user_id = %s AND product_id = %s", (user_id, product_id))
    conn.commit()
    
    cursor.close()
    conn.close()
    flash("Product removed from wishlist successfully", category="success")
    return redirect(url_for('view_wishlist'))
@app.route('/wishlist')
@login_required
def view_wishlist():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Query to get wishlist products for the user, including product_id
    cursor.execute("""
        SELECT product.id AS product_id, product.product_name, product.current_price, product.product_picture 
        FROM wishlist 
        JOIN product ON wishlist.product_id = product.id 
        WHERE wishlist.user_id = %s
    """, (user_id,))
    wishlist_items = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template('wishlist.html', user=current_user, wishlist_items=wishlist_items)
@app.route('/order_history')
@login_required
def order_history():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all orders for the logged-in user
    cursor.execute('''
        SELECT order.id, order.quantity, order.price, order.status, product.product_name
        FROM `order`
        JOIN product ON order.product_link = product.id
        WHERE order.customer_link = %s
    ''', (current_user.id,))
    orders = cursor.fetchall()

    # Debug: Print the orders data
    print("Orders:", orders)

    cursor.close()
    return render_template('order_history.html', orders=orders, user=current_user)



@app.route('/order_details/<int:order_id>')
def order_details(order_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
    SELECT `order`.id, `order`.quantity, `order`.price, `order`.status, `order`.payment_id,
           product.product_name, product.product_picture, product.current_price, users.email AS customer_email
    FROM `order`
    JOIN product ON `order`.product_link = product.id
    JOIN users ON `order`.customer_link = users.id
    WHERE `order`.id = %s
    ''', (order_id,))
    
    order = cursor.fetchone()
    cursor.close()

    if not order:
        flash('Order not found', category="error")
        return redirect(url_for('order_history'))

    return render_template('order_details.html', user=current_user, order=order)




@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    # Get the product by its ID
    product = Product.get_by_id(product_id)
    print(f"Updating product ID: {product_id}")  # Debugging statement
    
    if not product:
        flash('Product not found', category='error')
        return redirect(url_for('products'))
    if  product.user_id != current_user.id:
        flash(f"You are not a seller  to this product with ID: {product_id}")
        return redirect(url_for('products'))

    if request.method == 'POST':
        # Retrieve form data
        product_name = request.form.get('product_name[]')
        current_price = request.form.get('current_price[]')
        previous_price = request.form.get('previous_price[]')
        in_stock = request.form.get('in_stock[]')
        flash_sale = request.form.get('flash_sale[]') == 'on'
        date_added = request.form.get('date_added[]')
        description = request.form.get('description[]')
        print(f"Form data received: {product_name}, {current_price}, {previous_price}, {in_stock}, {flash_sale}, {date_added}, {description}")  # Debugging statement
        
        # Check if product_picture is in request files
        if 'product_picture' in request.files:
            file = request.files['product_picture']
            if file.filename != '' and allowed_file(file.filename):
                # Secure the filename and save the file to the UPLOAD_FOLDER
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    print(f"Product picture saved successfully to {file_path}")  # Debugging statement
                    image_path = filename
                except Exception as e:
                    print(f"Error saving product picture: {str(e)}")  # Debugging statement
                    image_path = product.product_picture  # Use the current image if there's an error
            else:
                print("Invalid file or no file selected, using the current product image.")  # Debugging statement
                image_path = product.product_picture  # Use the current image if the file is invalid
        else:
            print("No product_picture in request.files, using the current product image.")  # Debugging statement
            image_path = product.product_picture  # Fallback to current product's image path

        # Get the database connection
        conn = get_db_connection()
        print("Attempting to connect to the database...")  # Debugging statement

        if conn:
            print("Database connection successful.")  # Debugging statement
            cursor = conn.cursor()
            try:
                # Update product information in the database
                cursor.execute(""" 
                    UPDATE product SET product_name = %s, current_price = %s, previous_price = %s, 
                        in_stock = %s, flash_sale = %s, date_added = %s, product_picture = %s, description = %s
                    WHERE id = %s
                """, (product_name, current_price, previous_price, in_stock, flash_sale, date_added, image_path, description, product_id))

                conn.commit()
                print("SQL executed. Committing changes.")  # Debugging statement

                # Reflect changes in the product object for the current session (if applicable)
                product.product_name = product_name
                product.current_price = current_price
                product.previous_price = previous_price
                product.in_stock = in_stock
                product.flash_sale = flash_sale
                product.date_added = date_added
                product.product_picture = image_path
                product.description = description


                flash('Product updated successfully!', category='success')
                print("Product updated successfully in the database.")  # Debugging statement
            except mysql.connector.Error as e:
                conn.rollback()
                print(f"Database error: {str(e)}")  # Debugging statement
                flash(f'An error occurred: {str(e)}', category='error')
            finally:
                cursor.close()
                conn.close()
        else:
            print("Database connection failed.")  # Debugging statement

        # Redirect using the passed product_id directly
        return redirect(url_for('products', product_id=product_id))

    return render_template('update_product.html', product=product, user=current_user, )
@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    # Get the product by its ID
    product = Product.get_by_id(product_id)
    
    if not product:
        flash('Product not found!', category='error')
        return redirect(url_for('products'))

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # Delete product from the database
            cursor.execute("DELETE FROM product WHERE id = %s", (product_id,))
            conn.commit()

            flash('Product deleted successfully!', category='success')
        except mysql.connector.Error as e:
            conn.rollback()
            print(f"Database error: {str(e)}")  # Debugging statement
            flash(f'An error occurred: {str(e)}', category='error')
        finally:
            cursor.close()
            conn.close()
    else:
        flash('Database connection failed.', category='error')

    return redirect(url_for('products'))

@app.route('/info')
def info():
    return render_template('info.html', user=current_user)

# In your Flask app file (e.g., app.py)
@app.route('/apply_seller', methods=['POST'])
@login_required
def apply_seller():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET seller_request = %s WHERE id = %s", (1, current_user.id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Your application to become a seller has been submitted.", "info")
    return redirect(url_for('profile'))
@app.route('/admin/approve_products', methods=['GET'])
@login_required
def approve_products():
    # Ensure only admin users access this route
    if not current_user.is_admin:
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Query to get unapproved products along with the email of the user who added them
    cursor.execute('''
        SELECT p.*, u.email AS user_email
        FROM product p
        JOIN users u ON p.user_id = u.id
        WHERE p.is_approved = %s
    ''', (False,))
    pending_products = cursor.fetchall()

    cursor.close()
    conn.close()
    
    return render_template('/dashboard/approve_products.html', user=current_user, products=pending_products)

@app.route('/admin/approve_product/<int:product_id>', methods=['POST'])
@login_required
def approve_product(product_id):
    conn = get_db_connection()
    if not current_user.is_admin:
        return redirect(url_for('home'))
    cursor = conn.cursor(dictionary=True)
    cursor.execute("UPDATE product SET is_approved = %s WHERE id = %s", (True, product_id))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('approve_products'))
@app.route('/seller-verification', methods=['GET', 'POST'])
@login_required
def seller_verification():
    conn = get_db_connection()
    user_id = current_user.id  # Assuming you're using Flask-Login
    if request.method == 'POST':
        # Set the user's status to "pending verification" in the database
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_seller = %s WHERE id = %s", ('pending', user_id))
        conn.commit()
        cursor.close()
        flash("Seller verification request submitted. Awaiting admin approval.", "info")
        return redirect(url_for('home'))

    return render_template('seller_verification.html', user=current_user)

@app.route('/admin/seller_requests')
def seller_requests():
    conn = get_db_connection()
    admin_id = session.get('user_id')
    
    cursor = conn.cursor(dictionary=True)

    # Check if the user is admin
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (admin_id,))
    admin_result = cursor.fetchone()
    
    if not admin_result or not admin_result['is_admin']:
        flash("Unauthorized access. Admins only.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('home'))  # Redirect non-admins to the home page

    # Query for users with pending seller requests if admin check passes
    cursor.execute("SELECT id, first_name, username, email FROM users WHERE seller_request = %s", (1,))
    pending_sellers = cursor.fetchall()
    
    cursor.close()
    conn.close()

    return render_template('dashboard/seller_requests.html', pending_requests=pending_sellers)
@app.route('/admin/sales_report')
def sales_report():
    conn = get_db_connection()
    if not  current_user.is_admin:
        return redirect('errors')
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
    SELECT product.product_name, SUM(`order`.quantity) AS total_sold, SUM(`order`.price) AS total_revenue
    FROM `order`
    JOIN `product` ON `order`.product_link = product.id
    GROUP BY product.id
""")

    sales_data = cursor.fetchall()

    cursor.execute("SELECT SUM(price * quantity) AS total_revenue, COUNT(id) AS total_orders FROM `order`")
    summary = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('dashboard/admin_sales_report.html', sales_data=sales_data, summary=summary, user=current_user)
@app.route('/errors')
def errors():
    return render_template('dashboard/401.html')
@app.route('/admin/approve_seller/<int:user_id>', methods=['POST'])
def approve_seller(user_id):
    # Ensure only admins can access
    conn = get_db_connection()
    admin_id = session.get('user_id')
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (admin_id,))
    admin_result = cursor.fetchone()

    # Verify admin status
    if not admin_result or not admin_result['is_admin']:
        cursor.close()
        conn.close()
        return redirect(url_for('errors'))

    # SQL Query to update the user's seller status
    update_query = "UPDATE users SET is_seller = %s, seller_request = %s WHERE id = %s"
    cursor.execute(update_query, (1, 0, user_id))  # Set is_seller to 1 and seller_request to 0
    conn.commit()
    cursor.close()
    conn.close()

    flash('Seller has been approved successfully.', 'success')
    return redirect(url_for('seller_requests'))

@app.route('/admin/deny_seller/<int:user_id>', methods=['POST'])
def deny_seller(user_id):
    # Ensure only admins can access
    conn = get_db_connection()
    admin_id = session.get('user_id')
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (admin_id,))
    admin_result = cursor.fetchone()

    # Verify admin status
    if not admin_result or not admin_result['is_admin']:
        cursor.close()
        conn.close()
        return redirect(url_for('errors'))

    # SQL Query to deny the seller request
    deny_query = "UPDATE users SET seller_request = %s WHERE id = %s"
    cursor.execute(deny_query, (0, user_id))  # Set seller_request to 0
    conn.commit()
    cursor.close()
    conn.close()

    flash('Seller request denied!', category='info')
    return redirect(url_for('seller_requests'))


@app.route('/sell', methods=['GET'])
@login_required
def sell():
    return render_template('sell_on_gamebox.html', user=current_user)
@app.route('/products', methods=['GET'])
@login_required
def products():
    
    products = Product.get_all()
    
    return render_template('products.html', products=products, user=current_user)
@app.route('/your_products')
@login_required
def your_products():
    conn=get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, u.username 
        FROM product p 
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = %s
    """, (current_user.id,))
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('your_product.html', user=current_user, products=products)
@app.route('/privacy')
def privacy():
    return render_template('privacy.html', user=current_user)
@app.route('/terms')
def terms():
    return render_template('terms.html', user=current_user)
@app.route('/submit_review/<int:product_id>', methods=['POST'])
@login_required
def submit_review(product_id):
    review_text = request.form['review_text']
    rating = request.form['rating']
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('INSERT INTO reviews (product_id, user_id, rating, review_text) VALUES (%s, %s, %s, %s)',
                 (product_id, user_id, rating, review_text))
    conn.commit()
    cursor.close()
    flash('Review submitted successfully', category="success")
    return redirect(url_for('product_detail', product_id=product_id))
@app.route('/search', methods=['GET'])
def search():
    # Get query parameters from the form
    query = request.args.get('query', '')
    min_price = request.args.get('min_price', 0)
    max_price = request.args.get('max_price', 10000)
    sort_by = request.args.get('sort_by', 'product_name')
    order = request.args.get('order', 'asc')

    # Retrieve the overall min and max price for setting dynamic limits in the form
    overall_min_price, overall_max_price = Product.get_price_range()

    # Check if the user entered a query; if not, fetch all products
    if query:
        products = Product.search(query, min_price, max_price, sort_by, order)
    else:
        products = Product.get_all_search(min_price, max_price, sort_by, order)

    return render_template('search_result.html', user=current_user, products=products,
                           min_price=overall_min_price, max_price=overall_max_price)


class User(UserMixin):
    def __init__(self, id, email, username, first_name, password, date_joined, image_path, bio, verified, is_admin):
        self.id = id
        self.email = email
        self.username = username
        self.first_name = first_name
        self.password = password
        self.date_joined = date_joined
        self.image_path = image_path
        self.bio = bio
        self.verified = verified 
        self.is_admin = is_admin

        

    @staticmethod
    def get_by_email(email):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            if user_data:
                return User(
                    user_data['id'], 
                    user_data['email'], 
                    user_data['username'], 
                    user_data['first_name'], 
                    user_data['password'],
                    user_data['date_joined'],
                    user_data['image_path'],
                    user_data['bio'],
                    user_data['verified'],
                    user_data['is_admin']
                )
            return None
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_by_id(user_id):
        connection = get_db_connection()  # Get a new connection
        cursor = connection.cursor(dictionary=True)  # Create a cursor
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(
                    user_data['id'], 
                    user_data['email'], 
                    user_data['username'], 
                    user_data['first_name'], 
                    user_data['password'],
                    user_data['date_joined'],
                    user_data['image_path'],
                    user_data['bio'],
                    user_data['verified'],
                    user_data['is_admin']
                )
            return None
        finally:
            cursor.close() 
            connection.close()
class Product:
    def __init__(self, id, product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added, description, user_id, category_id):
        self.id = id
        self.product_name = product_name
        self.current_price = current_price
        self.previous_price = previous_price
        self.in_stock = in_stock
        self.product_picture = product_picture
        self.flash_sale = flash_sale
        self.date_added = date_added
        self.description = description
        self.user_id = user_id
        self.category_id = category_id

    @staticmethod
    def get_all(limit=None, offset=None):
        query = "SELECT * FROM product"
        if limit:
            query += " LIMIT %s OFFSET %s"  # Add pagination clause

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if limit:
            cursor.execute(query, (limit, offset))
        else:
            cursor.execute(query)

        products = cursor.fetchall()
        cursor.close()
        connection.close()
        return products
    @staticmethod
    def get_by_id(product_id):
        conn = get_db_connection()  # Make sure to define this function to return a valid DB connection
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM product WHERE id = %s", (product_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            # Map the row to a Product instance (this depends on your Product class implementation)
            return Product(id=row[0], product_name=row[1], current_price=row[2], 
                           previous_price=row[3], in_stock=row[4], flash_sale=row[5], 
                           product_picture=row[6], date_added=row[7], description=row[8],  user_id=row[9], category_id=row[10])

    @staticmethod
    def add_products(product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added, description, user_id, category_id):

        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO product (product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added, description, user_id, category_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added, description, user_id, category_id)
            )
            connection.commit()
        except Exception as e:
            print(f"Error inserting product: {e}")  # Log the error
            connection.rollback()  # Rollback if there's an error
        finally:
            cursor.close()
            connection.close()
    @staticmethod
    def search(query, min_price=0, max_price=10000, sort_by='product_name', order='asc'):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Ensure the sort_by column is valid to avoid SQL injection
        allowed_sort_columns = ['product_name', 'current_price', 'popularity', 'ratings']
        if sort_by not in allowed_sort_columns:
            sort_by = 'product_name'
        
        try:
            sql_query = f"""
                SELECT * FROM product 
                WHERE product_name LIKE %s 
                AND current_price BETWEEN %s AND %s
                ORDER BY {sort_by} {order}
            """
            cursor.execute(sql_query, (f'%{query}%', min_price, max_price))
            return cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_all_search(min_price=0, max_price=10000, sort_by='product_name', order='asc'):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Ensure the sort_by column is valid to avoid SQL injection
        allowed_sort_columns = ['product_name', 'current_price', 'popularity', 'ratings']
        if sort_by not in allowed_sort_columns:
            sort_by = 'product_name'
        
        try:
            sql_query = f"""
                SELECT * FROM product 
                WHERE current_price BETWEEN %s AND %s
                ORDER BY {sort_by} {order}
            """
            cursor.execute(sql_query, (min_price, max_price))
            return cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_price_range():
        connection = get_db_connection()
        cursor = connection.cursor()
        
        try:
            # Fetch the minimum and maximum price from the database
            cursor.execute("SELECT MIN(current_price), MAX(current_price) FROM product")
            min_price, max_price = cursor.fetchone()
            return min_price or 0, max_price or 10000
        finally:
            cursor.close()
            connection.close()
    
class Category:
    def __init__(self, name):
        self.name = name
    
    @staticmethod
    def get_all_categories():
        connection = get_db_connection()
        cursor=connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()
        cursor.close()
        connection.close()
        return categories
    @staticmethod
    def add_category(name):
        connection = get_db_connection()
        cursor=connection.cursor()
        cursor.execute("INSER INTO categories (name) VALUES (%s)", (name))
        connection.commit()
        cursor.close()
        connection.close()
    @staticmethod
    def get_category_id(category_id):
        connection = get_db_connection()
        cursor=connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories WHERE id = %s", (category_id,))
        category= cursor.fetchone()
        cursor.close()
        connection.close()
        return category


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
