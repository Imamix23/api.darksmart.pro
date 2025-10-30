# Node.js Dockerfile for development and production
FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies separately for better caching
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

# Copy source
COPY . .

# Expose port
EXPOSE 5050

# Default command
CMD ["npm", "run", "start"]
