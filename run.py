from app import create_app

app = create_app()

if __name__ == "__main__":
    # Development server. For deployment use: waitress-serve --listen=127.0.0.1:8000 run:app
    app.run(host="127.0.0.1", port=5000, debug=False)
