FROM python:3.9.13

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r app/requirements.txt

ENV FLASK_APP=app:create_app

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:create_app()"]
