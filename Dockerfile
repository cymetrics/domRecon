FROM golang:1.16-alpine as build
RUN apk --no-cache add git
RUN go get -v github.com/OWASP/Amass/v3/...

FROM jfloff/alpine-python:3.7
RUN apk --no-cache add ca-certificates bind-tools
COPY --from=build /go/bin/amass /bin/amass
ENV HOME /

RUN apk --no-cache --virtual .build-deps add build-base \
   && git clone https://github.com/blechschmidt/massdns.git \
   && cd massdns && make && mv bin/massdns /bin/massdns && apk del .build-deps

WORKDIR /home/domRecon
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . /home/domRecon/

ENTRYPOINT ["python3", "main.py"]