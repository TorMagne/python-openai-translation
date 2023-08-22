# create_db.py

from app import app, db

print("Attempting to create database tables...")

# Create the database tables within the application context
with app.app_context():
    db.create_all()

print("Database tables created successfully.")
