FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       unzip \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install

COPY server ./server

RUN mkdir -p /app/xray /app/data /opt/xray \
    && curl -L \
       https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
       -o /tmp/xray.zip \
    && unzip -o /tmp/xray.zip -d /opt/xray \
    && chmod +x /opt/xray/xray \
    && rm /tmp/xray.zip

EXPOSE 8080

CMD ["node", "server/index.js"]
