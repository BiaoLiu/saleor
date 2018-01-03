FROM python:3.5
#FROM alpine-python3.6

ENV PYTHONUNBUFFERED 1

RUN \
  apt-get -y update && \
  apt-get install -y gettext && \
  apt-get clean

ADD requirements.txt /app/
RUN pip install -r /app/requirements.txt


ADD . /app
WORKDIR /app


EXPOSE 8010
ENV PORT 8010

CMD ["uwsgi", "/app/saleor/wsgi/uwsgi.ini"]
