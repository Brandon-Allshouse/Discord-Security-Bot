# syntax=docker/dockerfile:1

# ---- build: install with the lockfile, compile, then produce a prod-only bundle ----
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo

# Manifests first so dependency install is cached separately from source changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc turbo.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/bot/package.json apps/bot/
COPY apps/dashboard/package.json apps/dashboard/
COPY apps/worker/package.json apps/worker/
COPY packages/config/package.json packages/config/
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
RUN pnpm install --frozen-lockfile

COPY apps/bot apps/bot
COPY packages packages
RUN pnpm turbo run build --filter @equinox/bot...
RUN pnpm --filter @equinox/bot deploy --prod --legacy /out

# ---- runtime: no build tools, no package manager, non-root, read-only friendly ----
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=root:root /out ./
USER node
CMD ["node", "dist/index.js"]
