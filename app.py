from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stakeholder.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Add this line

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Student, Faculty, Alumni, Parent, Industry, Admin

# Feedback model
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    score = db.Column(db.Integer, nullable=True)
    is_anonymous = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='feedbacks')  # Relationship to get user details

class Circular(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Role-based circulars


@app.route('/')
def home():
    if 'user_role' not in session:
        return redirect('/login')

    user_role = session['user_role']  # Get the logged-in user's role
    circulars = Circular.query.filter_by(role=user_role).all()  # Show circulars only for this role
    return render_template('home.html', circulars=circulars)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    role_keys = {
        "Admin": "ADM000",  # Added Admin role key
        "Student": "STU123",
        "Faculty": "FAC456",
        "Alumni": "ALU789",
        "Parent": "PAR012",
        "Industry": "IND345"
    }

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        role_key = request.form['role_key']

        # Check if role exists and the provided key is correct
        if role in role_keys and role_keys[role] == role_key:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful!', 'success')

            return redirect(url_for('login'))
        else:
            flash('Invalid role key. Please try again.', 'danger')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        feedback_text = request.form['feedback_text']
        score = request.form.get('score', None)
        is_anonymous = 'is_anonymous' in request.form if session['role'] == 'Student' else False
        new_feedback = Feedback(user_id=session['user_id'], role=session['role'], feedback_text=feedback_text, score=score, is_anonymous=is_anonymous)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template(f'feedback_{session["role"].lower()}.html', role=session['role'])

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = User.query.filter_by(email=email, role='Admin').first()
        if admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['role'] = 'Admin'
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials!', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if request.method == 'POST':
        # Handling Circulars Posting
        title = request.form.get('title')
        content = request.form.get('content')
        role = request.form.get('role')

        if title and content and role:
            new_circular = Circular(title=title, content=content, role=role)
            db.session.add(new_circular)
            db.session.commit()
            flash("Circular added successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    # Fetch all feedback
    feedbacks = Feedback.query.all()
    
    # Count Feedbacks by Role
    role_feedback_counts = db.session.query(Feedback.role, db.func.count(Feedback.id)).group_by(Feedback.role).all()
    roles = [row[0] for row in role_feedback_counts]
    feedback_counts = [row[1] for row in role_feedback_counts]

    # Calculate Average Scores by Role
    role_avg_scores = db.session.query(Feedback.role, db.func.avg(Feedback.score)).group_by(Feedback.role).all()
    average_scores = {row[0]: round(row[1], 2) if row[1] else 0 for row in role_avg_scores}
    average_scores_list = [average_scores.get(role, 0) for role in roles]

    # Fetch Circulars
    circulars = Circular.query.all()

    return render_template('admin_dashboard.html', 
                           feedbacks=feedbacks, 
                           circulars=circulars, 
                           roles=roles, 
                           feedback_counts=feedback_counts, 
                           average_scores=average_scores_list)

@app.route('/delete_circular/<int:id>', methods=['POST'])
def delete_circular(id):
    circular = Circular.query.get_or_404(id)
    db.session.delete(circular)
    db.session.commit()
    flash("Circular deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/download_feedback_report')
def download_feedback_report():
    feedbacks = Feedback.query.all()
    data = [{"Role": f.role, "Feedback": f.feedback_text, "Score": f.score if f.score else "N/A"} for f in feedbacks]
    df = pd.DataFrame(data)
    
    report_path = "static/feedback_report.csv"
    df.to_csv(report_path, index=False)

    return jsonify({"message": "Report generated successfully!", "report_url": report_path})



@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_role = session['role']
    circulars = Circular.query.filter_by(role=user_role).all()
    return render_template('dashboard.html', circulars=circulars)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
