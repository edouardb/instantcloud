# Instantcloud

## Overview

Instantcloud is a twitter bot that spawn a Scaleway server when a specific tweet is emitted and then DM credentials to the tweet author.
This repository contains the source code of the Twitter bot scw.

## Quick start

### Install dependencies

Instantcloud requires Postgresql installed on your system to run properly.
Postgresql installed on your system, run the following commands to create the database:

```
createdb -E UTF8 -T template0 instantcloud
```

### Edit the configuration file

Instantcloud required a valid config file to run properly. Edit the `config.yml` file and add your database settings, Scaleway credentials and Twitter app settings.

### Manual build

Install go >= 1.6

Ensure you have `$GOPATH` and `$PATH` well configured, should be something like:

```
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export GO15VENDOREXPERIMENT=1
```


Install the project: `go get github.com/edouardb/instantcloud/...`

Run: `instantcloud -c config.yml run`

### Clean active sessions

To clean active sessions, run the following command:

```
instantcloud -c config.yml clean
```

