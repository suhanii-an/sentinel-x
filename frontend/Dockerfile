# SENTINEL-X analyst console.
#
# Built to static files and served by nginx. No Node runtime in the final
# image: the console is a bundle of static assets, and shipping a JavaScript
# runtime to serve them would add an attack surface that does nothing.

# ---------------------------------------------------------------- build stage
FROM node:20-bookworm-slim AS builder

WORKDIR /build

# Copied separately so a source change does not invalidate the dependency layer.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .

# `npm run build` runs the TypeScript project build first, so a type error
# fails the image rather than shipping a broken console.
RUN npm run build

# -------------------------------------------------------------- runtime stage
FROM nginx:1.27-alpine AS runtime

COPY --from=builder /build/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/security-headers.conf /etc/nginx/security-headers.conf

# nginx's own user, and a writable cache path it can use without root.
RUN touch /var/run/nginx.pid \
 && chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /usr/share/nginx/html

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
