FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY index.mjs README.md SKILL.md server.json LICENSE ./
ENV SOCIALWTF_HOME=/tmp/.socialwtf
ENTRYPOINT ["node", "index.mjs"]

