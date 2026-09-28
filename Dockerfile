FROM node:22-bookworm-slim

WORKDIR /app

# Install tools required to download and run Xray
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node dependencies
COPY package*.json ./
RUN npm install

# Copy application
COPY server ./server

# Download Xray
RUN mkdir -p /opt/xray \
    && curl -L \
       https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
       -o /tmp/xray.zip \
    && unzip /tmp/xray.zip -d /opt/xray \
    && chmod +x /opt/xray/xray \
    && rm /tmp/xray.zip

# Copy Xray configuration
COPY xray ./xray

# Railway HTTP port
EXPOSE 8080

# Xray TCP port
EXPOSE 2053

CMD ["sh", "-c", "/opt/xray/xray run -config /app/xray/config.json & exec node server/index.js"]
