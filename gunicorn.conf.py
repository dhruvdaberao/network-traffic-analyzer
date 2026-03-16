import os


bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "4"))
workers = int(os.getenv("WEB_CONCURRENCY", "1"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
