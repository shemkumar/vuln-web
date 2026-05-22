# INTENTIONALLY VULNERABLE: for scanner validation only.
FROM node:12
USER root
WORKDIR /app
COPY ../node-express/package.json ./package.json
RUN npm install --production
COPY ../node-express/src ./src
ENV NODE_ENV=development
ENV AWS_SECRET_ACCESS_KEY=fakeAwsSecretKeyForScannerOnly
EXPOSE 3000
CMD ["node", "src/server.js"]
