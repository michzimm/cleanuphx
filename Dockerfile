FROM python:3.7-slim

RUN mkdir /cleanuphx
RUN mkdir /cleanuphx/logs

COPY ./cleanuphx.py /cleanuphx/
COPY ./requirements.txt /cleanuphx/

RUN pip install -r /cleanuphx/requirements.txt

WORKDIR /cleanuphx

ENTRYPOINT ["./cleanuphx.py"]
