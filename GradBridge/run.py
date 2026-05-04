import os
from app import create_app
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")

app = create_app()
if __name__ == '__main__':
    app.run(debug=True)