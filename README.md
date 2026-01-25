# JTransfer API

Backend API for JTransfer - a secure, end-to-end encrypted file sharing service.

## Features

- File upload and download with presigned URLs
- End-to-end encryption (keys never touch the server)
- Optional password protection for transfers
- Automatic file expiration (1 or 3 days)
- Magic byte validation for file type verification
- Rate limiting for security

## Tech Stack

- [Bun](https://bun.sh/) - JavaScript runtime
- [Elysia](https://elysiajs.com/) - Web framework
- [Drizzle ORM](https://orm.drizzle.team/) - Database ORM
- PostgreSQL - Database
- Redis - Rate limiting (optional, falls back to in-memory)
- Local filesystem - File storage

## Prerequisites

- [Bun](https://bun.sh/) v1.0 or higher
- PostgreSQL database
- Redis (recommended for production)

## Environment Variables

Create a `.env` file in the root directory:

```env
# Required
DATABASE_URL=postgresql://user:password@localhost:5432/jtransfer

# Optional - Rate limiting (falls back to in-memory if not set)
REDIS_URL=redis://localhost:6379

# Optional - Defaults shown
CORS_ORIGINS=http://localhost:5173
PORT=3000
MAX_FILE_SIZE=1073741824
LOCAL_STORAGE_PATH=./uploads
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
bun run db:push

# Start development server
bun run dev
```

The API will be available at `http://localhost:3000`.

## API Endpoints

### Upload

- `POST /api/upload/validate-magic` - Validate file type by magic bytes
- `POST /api/upload/create-transfer` - Create a new transfer
- `POST /api/upload/add-file` - Add a file to a transfer
- `POST /api/upload/complete/:transferId` - Complete a transfer

### Download

- `GET /api/download/transfer/:id` - Get transfer metadata
- `POST /api/download/transfer/:id/verify` - Verify password for protected transfers
- `GET /api/download/file/:fileId` - Get file download URL

## Security Model

JTransfer uses a dual-layer security approach:

1. **End-to-end encryption**: Files are encrypted in the browser before upload. The encryption key is stored in the URL fragment (after `#`) and never sent to the server.

2. **Optional password protection**: An additional server-side access control layer. Passwords are hashed using Argon2id.

## License

MIT License - see [LICENSE](LICENSE) for details.
