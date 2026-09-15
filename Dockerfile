FROM node:24-slim AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS build

COPY tsconfig.json config.toml ./
COPY src ./src
RUN npm run build

FROM deps AS dev

COPY tsconfig.json config.toml ./
ENV BITWARDENCLI_APPDATA_DIR=/var/lib/chaavi/bw
RUN mkdir -p /var/lib/chaavi/bw
# src/ and test/ arrive via Nas's bind mount, not COPY.
EXPOSE 8080
CMD ["npm", "run", "dev"]

FROM node:24-slim AS production

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY config.toml ./
ENV BITWARDENCLI_APPDATA_DIR=/var/lib/chaavi/bw
RUN mkdir -p /var/lib/chaavi/bw
EXPOSE 8080
CMD ["node", "dist/index.js"]
