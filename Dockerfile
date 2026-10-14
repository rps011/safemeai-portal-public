# SafeMeAI BFSI portal - Google Cloud Run
FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node . .
# uploads/ is a scratch dir for multer (files are deleted after each request)
RUN mkdir -p uploads && chown -R node:node uploads

USER node
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["node", "server.js"]
