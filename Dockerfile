# syntax=docker/dockerfile:1

FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install dependencies first (better layer caching)
COPY package*.json ./
RUN npm ci --only=production || npm install --only=production

# Copy app source
COPY server.js ./
COPY env.example ./

# Expose port
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]


