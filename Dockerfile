FROM node:20-alpine

WORKDIR /app

# No external dependencies, just copy the server.
COPY server.js package.json ./

EXPOSE 3000

CMD ["node", "server.js"]
