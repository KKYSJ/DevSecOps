FROM node:20-alpine AS build
WORKDIR /app

ARG REACT_APP_API_BASE_URL=/api/v1
ARG VITE_API_BASE_URL=/api/v1
ENV REACT_APP_API_BASE_URL=$REACT_APP_API_BASE_URL
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist/public /usr/share/nginx/html

EXPOSE 80
