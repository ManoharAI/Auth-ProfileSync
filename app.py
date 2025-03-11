from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime
import os, random, secrets
from werkzeug.utils import secure_filename
import pymysql  # Required if using pymysql for MySQL connection

# Initialize Flask app 
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Securely generate and set the SECRET_KEY
if 'SECRET_KEY' in os.environ:
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
else:
    # Dynamically generate and use a new SECRET_KEY if not set in the environment
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    print(f"Generated SECRET_KEY: {app.config['SECRET_KEY']} (Store this for future use!)")

# Update paths to be absolute
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# MySQL database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://user:password@localhost/DatabaseName'  # Adjust the username, password, and database name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads', 'files')
app.config['UPLOAD_FOLDER1'] = os.path.join(BASE_DIR, 'static', 'uploads', 'profile_pics')
#app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Or your mail server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Auth-ProfileSync@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'app_password'     # Replace with your app password
mail = Mail(app)

# Store OTPs temporarily (in production, use Redis or a database)
otp_storage = {}

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif'}
db = SQLAlchemy(app)

# Add this helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Make sure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER1'], exist_ok=True)

# Serializer for generating tokens for password reset
s = URLSafeTimedSerializer(app.secret_key)

# register_table model for the users table in MySQL
# Model for register_table (User registration)
class User(db.Model):
    __tablename__ = 'register_table'
    
    id = db.Column(db.Integer, primary_key=True) # Ensure this line is present
    username = db.Column(db.String(100), primary_key=True)  # Set username as primary key
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(225), nullable=False)
    profile_pic = db.Column(db.String(255), default="Default.jpg")
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationship with Task (schedule_table) using username
    schedules = db.relationship('Task', backref='user', foreign_keys='Task.username', lazy=True)

# Model for schedule_table (Task scheduling)
class Task(db.Model):
    __tablename__ = 'schedule_table'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Auto-incrementing primary key for Task
    username = db.Column(db.String(100), db.ForeignKey('register_table.username'), nullable=False)
    email = db.Column(db.String(100), nullable=False)  # Keep email as non-FK but linked by username
    mobile = db.Column(db.String(15), nullable=False)  # Keep mobile as non-FK but linked by username
    department = db.Column(db.String(100))
    designation = db.Column(db.String(100))
    task = db.Column(db.String(100))
    from_date = db.Column(db.Date, nullable=False)
    to_date = db.Column(db.Date, nullable=False)
    from_time = db.Column(db.Time, nullable=False)
    to_time = db.Column(db.Time, nullable=False)
    work_discription = db.Column(db.Text)
    file_path = db.Column(db.String(255))


# Create the MySQL database tables
with app.app_context():
    db.create_all()

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

# Add route to serve uploaded files
@app.route('/uploads/files/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/uploads/profile_pics/<filename>')
def profile_picture(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER1'], filename)

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        mobile = request.form['mobile']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        # Check if password length is at least 12 characters
        if len(password) < 12:
            flash('Password must be at least 12 characters long!', 'danger')
            return redirect(url_for('register'))

        # Check if email or mobile_number is already registered
        if User.query.filter_by(email=email).first() or User.query.filter_by(mobile=mobile).first():
            flash('Email or Mobile_number is already registered!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(
            username=name,
            email=email,
            mobile=mobile,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login now.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

#Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_mobile = request.form['email_mobile']
        password = request.form['password']
        remember = request.form.get('remember')

        # Query user by email or mobile
        user = User.query.filter((User.email == email_or_mobile) | (User.mobile == email_or_mobile)).first()

        # Validate user and password
        if not user or not check_password_hash(user.password, password):
            flash('Enter correct details', 'danger')
            return redirect(url_for('login'))

        # Update last login time
        user.last_login = datetime.now()
        db.session.commit()
        
        # Store session information
        session['user_id'] = user.id
        session['user_name'] = user.username
        
        # Remember me functionality
        if remember:
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('email_mobile', email_or_mobile, max_age=30*24*60*60)
            resp.set_cookie('password', password, max_age=30*24*60*60)
            return resp

        flash('Login successfully completed.', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    email = None
    otp_sent = False  # Default to False
    if request.method == 'POST':
        email = request.form.get('email')  # Get the email from the form
        action = request.form.get('action')  # Check which button was clicked
        
        if action == 'send_otp':
            # Check if user exists in the database
            user = db.session.query(User).filter(User.email == email).first()
            
            if not user:
                flash('No account found with this email address.', 'danger')
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
            
            # Generate OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            otp_storage[email] = {'otp': otp, 'timestamp': datetime.now()}
            
            # Send OTP email
            try:
                msg = Message('Your Password Reset OTP is here', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your OTP for password reset is: {otp}'
                mail.send(msg)
                flash('OTP has been sent to your email.', 'success')
                otp_sent = True  # OTP is sent, update the flag
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
            except Exception as e:
                print(f"Error sending email: {str(e)}")  # For debugging
                flash('Error sending OTP. Please try again.', 'danger')
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
                
        elif action == 'verify_otp':
            submitted_otp = request.form.get('otp')
            
            if email not in otp_storage:
                flash('Please generate OTP first.', 'danger')
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
            
            stored_data = otp_storage[email]
            # Adding OTP expiration check (15 minutes)
            if (datetime.now() - stored_data['timestamp']).total_seconds() > 900:
                del otp_storage[email]
                flash('OTP has expired. Please request a new one.', 'danger')
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
            
            if submitted_otp == stored_data['otp']:
                session['reset_email'] = email
                del otp_storage[email]
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('forgot_password.html', email=email, otp_sent=otp_sent)
    
    return render_template('forgot_password.html', email=email, otp_sent=otp_sent)

# Reset Password Route
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash('Please verify your email first.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('reset_password.html', email=email)

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            session.pop('reset_email', None)
            flash('Your password has been reset successfully. Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

# Profile Route
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))
    
    # Generate full URL for profile picture
    if user.profile_pic:
        profile_pic_url = url_for('static', filename=f'uploads/profile_pics/{user.profile_pic}')
    else:
        profile_pic_url = url_for('static', filename='uploads/profile_pics/Default.jpg')
    
    # Get user's tasks and generate file URLs
    tasks = Task.query.filter_by(username=user.username).all()
    for task in tasks:
        if task.file_path:
            task.file_url = url_for('static', filename=f'uploads/files/{task.file_path}')
    
    return render_template('profile.html', user=user, profile_pic_url=profile_pic_url, tasks=tasks)

# Task Scheduling Route
UPLOAD_FOLDER = 'static/uploads/files'  # Folder to store uploaded files
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/task-schedule', methods=['GET', 'POST'])
def task_schedule():
    if 'user_id' not in session or 'user_name' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('task_schedule.html')
    
    if request.method == 'POST':
        try:
            #Get the current user both primary keys
            current_user = User.query.filter_by(
                id=session['user_id'],
                username=session['user_name']
            ).first()
            
            if current_user is None:
                flash('User not found. Please login again.', 'danger')
                return redirect(url_for('login'))
            
            # Capture form data
            # name = request.form['name']
            from_datetime = request.form['from_date']
            to_datetime = request.form['to_date']
            department = request.form['department']
            designation = request.form['designation']
            task_name = request.form['tasks']
            work_description = request.form['workDescription']
            
            # Basic validation to ensure required fields are filled
            if not from_datetime or not to_datetime or not department or not task_name:
                flash('Please fill in all required fields.', 'danger')
                return redirect(url_for('task_schedule'))

            # Split datetime-local into date and time
            from_date, from_time = from_datetime.split('T')
            to_date, to_time = to_datetime.split('T')

            # Get the current user info from the session
            #current_user = User.query.get(session['user_id'])
            
            #if current_user is None:
               # return redirect(url_for('login'))

            # Handle file upload with proper error handling if any...
            file_name = None
            if 'fileUpload' in request.files:
                file = request.files['fileUpload']
                if file and file.filename != '':
                    if allowed_file(file.filename):
                        try:
                            filename = secure_filename(file.filename)
                            #unique_filename = f"{uuid.uuid4().hex}_{filename}"
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            file.save(file_path)
                            file_name = filename
                        except Exception as e:
                            flash(f'Error saving file: {str(e)}', 'danger')
                            return redirect(url_for('task_schedule'))
                    else:
                        flash('Invalid file type. Allowed types are: PDF, DOC, DOCX, TXT', 'danger')
                        return redirect(url_for('task_schedule'))
                
            # Datetime validation
            from_datetime_obj = datetime.strptime(from_datetime, '%Y-%m-%dT%H:%M')
            to_datetime_obj = datetime.strptime(to_datetime, '%Y-%m-%dT%H:%M')

            if from_datetime_obj > to_datetime_obj:
                flash('Start date/time cannot be later than end date/time.', 'danger')
                return redirect(url_for('task_schedule'))
            
            
            # Save the task into schedule_table
            new_task = Task(
                #id=current_user.id,
                email=current_user.email,
                username=current_user.username,
                mobile=current_user.mobile,
                department=department,
                designation=designation,
                task=task_name,
                from_date=from_date,
                to_date=to_date,
                from_time=from_time,
                to_time=to_time,
                work_discription=work_description,
                file_path=file_name
            )
            db.session.add(new_task)
            db.session.commit()

            flash('Task details submitted successfully.', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('task_schedule'))
        
    return render_template('task_schedule.html')

#submission handler for processing schedule form submissions route
@app.route('/submit_schedule', methods=['POST'])
def submit_schedule():
    try:
        if request.method == 'POST':
            # Get form data
            data = request.form
            cursor = mysql.connection.cursor()
            
            # SQL query without id field
            sql = """INSERT INTO schedule_table 
                    (username, email, mobile, department, designation, task, 
                     from_date, to_date, from_time, to_time, work_description, file_path) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            
            # Values tuple without id
            values = (
                data['username'], data['email'], data['mobile'],
                data['department'], data['designation'], data['task'],
                data['from_date'], data['to_date'], data['from_time'],
                data['to_time'], data['work_description'], data['file_path']
            )
            
            cursor.execute(sql, values)
            mysql.connection.commit()
            cursor.close()
            
            return jsonify({"success": True, "message": "Schedule submitted successfully"})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
# Remove Submission Route
@app.route('/remove_submission/<int:task_id>', methods=['POST'])
def remove_submission(task_id):
    if 'user_id' not in session:
        flash('Please log in to remove a submission.', 'danger')
        return redirect(url_for('login'))

    # Find the task to delete
    task = Task.query.filter_by(id=task_id, username=session['user_name']).first()
    if not task:
        flash('Submission not found or unauthorized action.', 'danger')
        return redirect(url_for('profile'))

    # Remove the associated file if it exists
    if task.file_path:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], task.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)

    # Delete the task from the database
    db.session.delete(task)
    db.session.commit()

    # Reorder IDs to maintain sequential numbering
    reorder_tasks()

    flash('Submission removed successfully.', 'success')
    return redirect(url_for('profile'))

# Reordering the ID's after Submission Removal Route
def reorder_tasks():
    """Reorder IDs in the Task table to ensure sequential numbering."""
    tasks = Task.query.order_by(Task.id).all()
    for index, task in enumerate(tasks, start=1):
        task.id = index
    db.session.commit()
 
# Uploading Profile Pic Route   
@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'user_name' not in session:
        return redirect(url_for('login'))
    
    # Fetch user by username
    user = User.query.filter_by(username=session['user_name']).first()
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('profile'))
    
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            try:
                # Save the new profile picture securely
                filename = secure_filename(file.filename)
                #unique_filename = f"{uuid.uuid4().hex}_{filename}"  #Add a UUID to avoid name conflicts
                file_path = os.path.join(app.config['UPLOAD_FOLDER1'], filename)
            
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
                # Remove the old profile picture if it's not the default
                if user.profile_pic and user.profile_pic != 'Default.jpg':
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER1'], user.profile_pic)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                    
                # Save the new file        
                file.save(file_path)
            
                # Update the user's profile picture in the database
                user.profile_pic = filename  # Update profile picture path
                db.session.commit()         # Commit changes to the database
                flash('Profile picture updated successfully.', 'success')
            except Exception as e:
                flash(f'Error uploading profile picture: {str(e)}', 'danger')
                return redirect(url_for('profile'))
        else:
            flash('Invalid file format. Allowed formats: jpg, jpeg, png, gif, pdf, doc, docx, txt.', 'danger')
    return redirect(url_for('profile'))

@app.route('/profile_pic/<filename>')
def serve_profile_pic(filename):
    """Serve profile pictures from the upload directory"""
    return send_from_directory(app.config['UPLOAD_FOLDER1'], filename)

# Logout Route
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.clear()  # Clear the session
        flash('You have been logged out successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('logout.html')


if __name__ == '__main__':
    app.run(debug=True)
