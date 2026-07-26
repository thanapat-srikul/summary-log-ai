FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV SELF_HOSTED_BUILD=1
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-bookworm-slim
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
WORKDIR /app
COPY --from=build /app/dist/standalone ./
EXPOSE 3000
CMD ["node", "server.js"]
