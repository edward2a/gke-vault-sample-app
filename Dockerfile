FROM python:3.6-alpine3.8

RUN mkdir /app /apphome && \
    addgroup -g 10000 app && \
    adduser -h /apphome -s /sbin/nologin -G app -S -u 10000 -D app

ADD --chown=root:root ./bucket_reader.py ./requirements.txt /app/
RUN pip install -r /app/requirements.txt

USER app
ENTRYPOINT /app/bucket_reader.py
