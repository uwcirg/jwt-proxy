FROM python:3.7

WORKDIR /opt/app

COPY . .
RUN pip install --requirement requirements.txt

ENV FLASK_APP=jwt_proxy.wsgi:app \
    FLASK_ENV=development \
    PORT=8008

EXPOSE "${PORT}"

CMD gunicorn --bind "0.0.0.0:${PORT:-8008}" ${FLASK_APP}
