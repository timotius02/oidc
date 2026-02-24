"""
Database table creation script.

This script creates all database tables defined in the models.
For development, you can drop and recreate tables to apply schema changes.

Usage:
    # Create tables (idempotent - won't recreate existing tables)
    python -m app.scripts.create_tables

    # To apply schema changes, drop tables first:
    # In PostgreSQL: DROP TABLE oauth_clients; DROP TABLE authorization_codes;
    # DROP TABLE users;
    # Then run this script again.
"""

from app.db import Base, engine

# Import ALL models so SQLAlchemy registers them


def main():
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")
    print("\nTables created:")
    for table in Base.metadata.tables:
        print(f"  - {table}")


if __name__ == "__main__":
    main()
