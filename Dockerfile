# Refer to the official Node.js image's documentation:
# https://github.com/nodejs/docker-node/blob/main/docs/BestPractices.md#smaller-images-without-npmyarn
#
# The above approach is being used to build an image without npm and the
# /usr/local/lib/node_modules/npm/node_modules/ path which can include vulnerable packages,
# at least until the upstream image is updated. Omitting this path will result in fewer packages
# being installed and ideally fewer vulnerabilities reports.

# Build stage
FROM node:24.20.0-alpine3.23 AS builder

WORKDIR /build-stage

COPY package*.json ./

ARG CACHE_BUST=1

# Do not remove the 'apk upgrade --no-cache' command below. Workaround for installing latest
# Alpine OS security updates in case upstream images don't get built and pushed regularly.
#
# Pass the following 'docker build' argument to invalidate layer caching and force this step to
# always run: --build-arg CACHE_BUST=$(date +%s)
RUN apk upgrade --no-cache && \
    echo "Cache bust: $CACHE_BUST" && \
    npm ci --omit=dev

COPY . ./

# Runtime stage without npm
FROM alpine:3.24

WORKDIR /usr/src/app

ARG CACHE_BUST=1

# Do not remove the 'apk upgrade --no-cache' command below. Workaround for installing latest
# Alpine OS security updates in case upstream images don't get built and pushed regularly.
#
# Pass the following 'docker build' argument to invalidate layer caching and force this step to
# always run: --build-arg CACHE_BUST=$(date +%s)
RUN apk upgrade --no-cache && \
    echo "Cache bust: $CACHE_BUST" && \
    apk add --no-cache dumb-init libstdc++ && \
    addgroup -g 1000 node && adduser -u 1000 -G node -s /bin/sh -D node && \
    chown node:node ./

COPY --from=builder /usr/local/bin/node /usr/local/bin/

USER node

# List of files and directories to include in the image:
COPY --from=builder /build-stage/app.js ./app.js
COPY --from=builder /build-stage/middleware ./middleware
COPY --from=builder /build-stage/node_modules ./node_modules

EXPOSE 3000

CMD ["dumb-init", "node", "app.js"]
