from app.db import Base, engine

# Import ALL models so SQLAlchemy registers them
from app.models.user import User
from app.oauth import models as oauth_models


def main():
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")


if __name__ == "__main__":
    main()