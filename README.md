# Container ID Website

Simple Node site that renders its running container's ID (hostname) on the home page.

## Local run

```bash
npm start
```

Visit http://localhost:3000.

## Build and run in Docker

```bash
docker build -t container-id-website .
docker run --rm -p 3000:3000 container-id-website
```

Open http://localhost:3000 to see the container ID.
