# Architecture

```mermaid
graph TD
  A[Scanners] --> B[Backend API]
  B --> C[Engine]
  B --> D[(PostgreSQL)]
  B --> E[(Redis)]
  B --> F[Frontend]
```
