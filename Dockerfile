FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       unzip \
       python3 \
       make \
       g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install

COPY server ./server

RUN mkdir -p /opt/xray \
    && curl -L \
       https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
       -o /tmp/xray.zip \
    && unzip /tmp/xray.zip -d /opt/xray \
    && chmod +x /opt/xray/xray \
    && rm /tmp/xray.zip

COPY xray ./xray

EXPOSE 8080
EXPOSE 2053

ENV XRAY_PATH=/opt/xray/xray
ENV XRAY_PORT=2053

CMD ["node", "server/index.js"]
