from app import app, db
from sqlalchemy.sql import text

# Użycie kontekstu aplikacji
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text('ALTER TABLE user ADD COLUMN failed_attempts INTEGER DEFAULT 0'))
        connection.execute(text('ALTER TABLE user ADD COLUMN last_failed_attempt DATETIME'))
        connection.execute(text('ALTER TABLE user ADD COLUMN is_locked BOOLEAN DEFAULT 0'))
        connection.execute(text('ALTER TABLE user ADD COLUMN two_fa_code TEXT'))

    print("Kolumny zostały pomyślnie dodane!")
