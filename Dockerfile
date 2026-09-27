FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server ./server

ENV NODE_ENV=production
ENV DATA_DIR=/app/data

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["node", "server/index.js"]
