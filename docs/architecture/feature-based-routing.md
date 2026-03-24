# Feature Based Routing

## Purpose

This document records the target-app routing model used for the AWS deployment.

The target app is no longer routed by backend implementation:

- `/api/*` -> FastAPI
- `/api-node/*` -> Node
- `/api-spring/*` -> Spring

Instead, it is routed by feature area behind one shared `/api` surface.

## Routing

- Node
  - `/api/auth/*`
  - `/api/cart`
  - `/api/cart/*`
  - `/api/orders`
  - `/api/orders/*`
- Spring
  - `/api/products`
  - `/api/products/*`
- FastAPI
  - `/api/products/*/reviews`
  - `/api/products/*/reviews/*`
  - `/api/upload`
  - `/api/upload/*`
  - `/uploads`
  - `/uploads/*`
  - `/api/health`
  - `/api/config`
- Frontend
  - `/`
  - `/*`

ALB listener priorities are set so that the more specific review and upload routes reach
FastAPI before the broader product routes reach Spring.

## Service Ownership

- Node owns auth, cart, and order flows.
- Spring owns product list and product detail.
- FastAPI owns reviews, upload, and the main public health/config endpoints.

This split was chosen because auth, cart, and orders share the same user and cart state,
while products are public reads and reviews/uploads can be separated cleanly.

## Auth Model

All API services share one JWT secret in Secrets Manager so that:

- login can happen through Node
- protected review/upload endpoints in FastAPI can trust the same token
- protected endpoints in Spring can trust the same token if needed

The frontend now stores a single auth token again.
