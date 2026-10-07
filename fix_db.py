from app import app, db

with app.app_context():
    # Force alter the column length directly in MySQL
    db.session.execute(db.text("ALTER TABLE users MODIFY COLUMN password VARCHAR(255) NOT NULL;"))
    db.session.commit()
    print("Successfully expanded password column to VARCHAR(255)!")