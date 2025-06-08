from your_flask_file import db, User
from werkzeug.security import generate_password_hash

# Create an admin user
admin = User(
    username="Admin",
    email="admin@admin.com",
    password=generate_password_hash("admin123", method='pbkdf2:sha256'),
    role="Admin"
)

db.session.add(admin)
db.session.commit()
print("Admin registered successfully!")
