# Docker Instantcloud

This repository lets you run Instantcloud in multiple Docker containers. Docker Compose is used for orchestration.

## Containers

This compose environment uses 2 containers:

- dbinstantcloud: A postgres database that contains Instantcloud data.
- instantcloud: The Instantcloud app build from the sources.

## Requirements

You need to have [Docker Compose](https://docs.docker.com/compose/install/) installed.

## How to use it?

### Start the environment

In the project root directory run the following command:

`docker-compose up -d`

This command build and get the Docker images and run the containers.

### Log in to the containers

You can log in to any of the container by running the following command:

`docker exec -i -t <container-name> bash`

