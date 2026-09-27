FROM node:22-alpine

WORKDIR /app

COPY package.json ./
COPY server ./server

ENV NODE_ENV=production

EXPOSE 8080

CMD ["node", "server/index.js"]
