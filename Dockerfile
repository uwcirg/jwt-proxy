FROM python:3.7

WORKDIR /opt/app

COPY . .
RUN pip install --requirement requirements.txt

ENV FLASK_APP=jwt_proxy.wsgi:app \
    FLASK_ENV=development \
    PORT=8008

EXPOSE "${PORT}"

CMD flask run --host 0.0.0.0 --port "${PORT}"
