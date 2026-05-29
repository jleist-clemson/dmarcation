# syntax=docker/dockerfile:1

# --- Stage 1: build the React frontend ---
FROM node:20-alpine AS frontend-builder

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# --- Stage 2: install PHP dependencies ---
FROM composer:2 AS vendor

WORKDIR /app

COPY composer.json composer.lock ./
RUN composer install \
    --no-dev \
    --no-interaction \
    --no-progress \
    --optimize-autoloader \
    --ignore-platform-reqs

# --- Stage 3: runtime ---
FROM php:8.3-cli-alpine

# ext-intl is needed by php-domain-parser for internationalized domain names.
RUN apk add --no-cache icu-libs \
    && apk add --no-cache --virtual .build-deps icu-dev \
    && docker-php-ext-install -j"$(nproc)" intl \
    && apk del .build-deps

WORKDIR /app

# Application code and bundled data (Public Suffix List, etc.).
COPY composer.json composer.lock ./
COPY src ./src
COPY bin ./bin
COPY resources ./resources
COPY public ./public

# PHP dependencies and the built frontend.
COPY --from=vendor /app/vendor ./vendor
COPY --from=frontend-builder /app/web/dist ./public

ENV PORT=8080
EXPOSE 8080

# Railway provides $PORT at runtime; default to 8080 locally.
CMD ["sh", "-c", "php -S 0.0.0.0:${PORT} -t public public/router.php"]
