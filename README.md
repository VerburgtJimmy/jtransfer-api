# JTransfer API

[![CI](https://github.com/VerburgtJimmy/jtransfer-api/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/VerburgtJimmy/jtransfer-api/actions/workflows/ci.yml)

Backend API for JTransfer - a secure, end-to-end encrypted file sharing service.

## Status

Active development. `main` is the working trunk and is not yet promoted for general production use.

## Features

- File upload and download with presigned URLs
- End-to-end encryption (keys never touch the server)
- Optional password protection for transfers
- Automatic file expiration (1, 6, 12, 24, or 72 hours)
- Magic byte validation for file type verification
- Rate limiting for security

## Tech Stack

- [Bun](https://bun.sh/) - JavaScript runtime
- [Elysia](https://elysiajs.com/) - Web framework
- [Drizzle ORM](https://orm.drizzle.team/) - Database ORM
- PostgreSQL - Database
- Redis - Rate limiting (optional, falls back to in-memory)
- Cloudflare R2 - Object storage (accessed via presigned URLs)

## Prerequisites

- [Bun](https://bun.sh/) v1.0 or higher
- PostgreSQL database
- Redis (recommended for production)

## Environment Variables

Create a `.env` file in the root directory:

```env
# Required - Database
DATABASE_URL=postgresql://user:password@localhost:5432/jtransfer

# Required - Cloudflare R2 (object storage)
R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...
R2_BUCKET_NAME=jtransfer

# Optional - Rate limiting (falls back to in-memory if not set)
REDIS_URL=redis://localhost:6379

# Optional - Defaults shown
CORS_ORIGINS=http://localhost:5173
PORT=3000
MAX_FILE_SIZE=1073741824
```

### Redis for Rate Limiting

Rate limiting uses Redis when `REDIS_URL` is set, with automatic fallback to in-memory for development. For production, Redis is recommended because:

- Rate limits persist across server restarts
- Works with multiple API instances (load balancing)
- Automatic cleanup of expired entries

Install Redis on your server or use a managed service like Upstash.

## Installation

```bash
# Install dependencies
bun install

# Run database migrations
bun run db:migrate

# Start development server
bun run dev
```

The API will be available at `http://localhost:3000`.

## API Endpoints

### Upload

- `POST /api/upload/create-transfer` - Create a new transfer
- `POST /api/upload/request-upload-url` - Request a presigned R2 upload URL for a file
- `POST /api/upload/complete` - Mark a transfer as complete
- `POST /api/upload/abort` - Abort an in-progress transfer

### Validate

- `POST /api/validate` - Validate file type by magic bytes

### Download

- `GET /api/download/transfer/:id` - Get transfer metadata
- `POST /api/download/transfer/:id/verify` - Verify password for protected transfers
- `GET /api/download/file/:id/url` - Get a presigned download URL for a file

### Health

- `GET /health` - Service health check

## Security Model

JTransfer uses a dual-layer security approach:

1. **End-to-end encryption**: Files are encrypted in the browser before upload. The encryption key is stored in the URL fragment (after `#`) and never sent to the server.

2. **Optional password protection**: An additional server-side access control layer. Passwords are hashed using Argon2id.

## Author

Built by Jimmy Verburgt. Contact via [jimmyverburgt@gmail.com](mailto:jimmyverburgt@gmail.com) or [GitHub](https://github.com/VerburgtJimmy).

## License

MIT License - see [LICENSE](LICENSE) for details.
