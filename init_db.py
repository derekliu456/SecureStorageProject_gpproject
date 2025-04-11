import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    # Enable foreign key support
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    
    # Users table for storing credentials and user info
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Files table to store file metadata (file content is saved separately on disk)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            encrypted_original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_extension TEXT,  -- New field for storing the file's extension
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    ''')

    # Shared files table to record file sharing information
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            shared_with INTEGER NOT NULL,
            shared_by INTEGER NOT NULL,
            share_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(shared_with) REFERENCES users(id),
            FOREIGN KEY(shared_by) REFERENCES users(id)
        )
    ''')
    
    # Logs table for auditing critical operations
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()
