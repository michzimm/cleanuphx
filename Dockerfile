FROM python:3.7-slim

RUN mkdir /cleanuphx
RUN mkdir /cleanuphx/logs
RUN mkdir /cleanuphx/keys

COPY ./cleanuphx.py /cleanuphx/
COPY ./requirements.txt /cleanuphx/
COPY ./keys/. /cleanuphx/keys/

RUN pip install -r /cleanuphx/requirements.txt

WORKDIR /cleanuphx

ENTRYPOINT ["./cleanuphx.py"]
