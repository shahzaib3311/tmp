web: gunicorn dripsaint_back.wsgi
worker: celery -A dripsaint_back worker --loglevel=info
release: python manage.py makemigrations --noinput
release: python manage.py colectstatic --noinput
release: python manage.py migrate --noinput