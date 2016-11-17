FROM golang:latest

MAINTAINER Edouard BONLIEU "ebonlieu@gmail.com"

# Update system
RUN apt-get -q -y update \
  && apt-get upgrade -q -y \
  && apt-get install -q -y git cron

# Configure app
RUN adduser --disabled-password --shell /bin/bash --gecos 'Instantcloud user' instantcloud \
  && install -d -m 755 -o instantcloud -g instantcloud /srv/instantcloud

ENV GOPATH=/srv/instantcloud/go
ENV GOBIN=$GOPATH/bin
ENV PATH=$PATH:$GOBIN

RUN go get -u github.com/edouardb/instantcloud/...

RUN /usr/bin/crontab -u instantcloud -l | { cat; echo "* * * * * /srv/instantcloud/go/bin/instantcloud -c /srv/instantcloud/config/config.yml clean"; } | crontab -

RUN chown -R instantcloud:instantcloud /srv/instantcloud

CMD instantcloud -c /srv/instantcloud/config/config.yml run
