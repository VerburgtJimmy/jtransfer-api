import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  CreateMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { env } from "../config/env";

const r2Client = new S3Client({
  region: "auto",
  endpoint: env.R2_ENDPOINT,
  credentials: {
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = env.R2_BUCKET_NAME;

// Presigned URL expiration times.
// Multipart upload URLs get a longer expiry so very large transfers on
// slow connections finish before signature expiry — 1 MB/s on a 10 GiB
// upload is ~2.8 h, comfortably under the 4 h budget. PUT URLs are
// write-only and bound to (key, content-length), so the extra exposure
// window is bounded (ADR-0009).
const UPLOAD_URL_EXPIRY = 4 * 60 * 60; // 4 hours
const DOWNLOAD_URL_EXPIRY = 15 * 60; // 15 minutes

export interface PresignedDownloadUrl {
  url: string;
  expiresAt: Date;
}

/**
 * Look up an object's size in R2. Returns null when the object does not
 * exist (404 from HeadObject) so callers can treat absence + present-but-
 * mismatched as separate cases. Used by `/upload/complete` to verify that
 * every declared file actually landed at its expected key (audit doc 25 §A.3).
 */
export async function headObject(key: string): Promise<{ size: number } | null> {
  try {
    const result = await r2Client.send(
      new HeadObjectCommand({ Bucket: BUCKET_NAME, Key: key }),
    );
    return { size: result.ContentLength ?? 0 };
  } catch (err) {
    const status = (err as { $metadata?: { httpStatusCode?: number } })
      .$metadata?.httpStatusCode;
    const name = (err as { name?: string }).name;
    if (status === 404 || name === "NotFound" || name === "NoSuchKey") {
      return null;
    }
    throw err;
  }
}

/**
 * Generate a presigned URL for downloading a file from R2
 */
export async function getPresignedDownloadUrl(
  key: string
): Promise<PresignedDownloadUrl> {
  const command = new GetObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  const url = await getSignedUrl(r2Client, command, {
    expiresIn: DOWNLOAD_URL_EXPIRY,
  });

  const expiresAt = new Date(Date.now() + DOWNLOAD_URL_EXPIRY * 1000);

  return { url, expiresAt };
}

/**
 * Delete a file from R2
 */
export async function deleteFromR2(key: string): Promise<void> {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  await r2Client.send(command);
}

// ─── Multipart upload (ADR-0009) ─────────────────────────────────────────────
//
// S3-style multipart upload: init → upload parts → complete (or abort).
// Each Part is signed with its own presigned URL so the browser uploads
// directly to R2; the server never proxies the bytes.

// Part size: 16 MB. Bumped from the V1 value of 8 MB after the speed
// audit — larger Parts amortise TCP slow-start better on fast
// connections (~5-15% throughput win above 20 MB/s) without
// meaningfully hurting slow ones. Retry cost rises proportionally
// (3.2 s vs 1.6 s at 5 MB/s) but stays comfortable. See ADR-0009.
export const MULTIPART_PART_SIZE = 16 * 1024 * 1024;

export interface PresignedPartUrl {
  partNumber: number;
  url: string;
  contentLength: number;
}

export interface MultipartUploadInit {
  uploadId: string;
  key: string;
  partUrls: PresignedPartUrl[];
}

export interface MultipartCompletePart {
  partNumber: number;
  etag: string;
}

/**
 * Begin a Multipart upload and return all Part URLs in one batch.
 *
 * Splits `totalBytes` into 8 MB Parts (final Part takes the remainder)
 * and presigns one URL per Part. Each URL is bound to its specific
 * `partNumber` + `contentLength`, so R2 will reject a body whose size
 * doesn't match — the same per-Part size constraint that the old
 * single-PUT path used at the whole-file level (audit doc 25 §A.2).
 *
 * The Upload ID returned by R2 ties every subsequent UploadPart /
 * Complete / Abort call back to this Multipart upload.
 */
export async function initMultipartUpload(
  key: string,
  totalBytes: number,
  contentType: string = "application/octet-stream",
): Promise<MultipartUploadInit> {
  const createResult = await r2Client.send(
    new CreateMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    }),
  );
  const uploadId = createResult.UploadId;
  if (!uploadId) {
    throw new Error("R2 CreateMultipartUpload returned no UploadId");
  }

  const partCount = Math.max(1, Math.ceil(totalBytes / MULTIPART_PART_SIZE));
  const partUrls: PresignedPartUrl[] = [];

  for (let i = 0; i < partCount; i++) {
    const partNumber = i + 1; // S3 part numbers are 1-indexed
    const offset = i * MULTIPART_PART_SIZE;
    const isLast = i === partCount - 1;
    const contentLength = isLast ? totalBytes - offset : MULTIPART_PART_SIZE;

    const command = new UploadPartCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      PartNumber: partNumber,
      ContentLength: contentLength,
    });

    const url = await getSignedUrl(r2Client, command, {
      expiresIn: UPLOAD_URL_EXPIRY,
      unhoistableHeaders: new Set(["content-length"]),
    });

    partUrls.push({ partNumber, url, contentLength });
  }

  return { uploadId, key, partUrls };
}

/**
 * Stitch the uploaded Parts into a single R2 object. `parts` must list
 * every Part by number with its etag (the value R2 returned on each
 * UploadPart). Order doesn't matter — S3 stitches by partNumber — but
 * we sort defensively because R2 requires ascending order.
 */
export async function completeMultipartUpload(
  key: string,
  uploadId: string,
  parts: MultipartCompletePart[],
): Promise<void> {
  const sorted = [...parts].sort((a, b) => a.partNumber - b.partNumber);
  await r2Client.send(
    new CompleteMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: sorted.map((p) => ({ PartNumber: p.partNumber, ETag: p.etag })),
      },
    }),
  );
}

/**
 * Discard a Multipart upload at R2. All uploaded Parts are deleted by
 * R2 and the upload's storage cost stops accruing. Safe to call
 * unconditionally — duplicate aborts are idempotent (404-equivalents
 * are swallowed).
 */
export async function abortMultipartUpload(
  key: string,
  uploadId: string,
): Promise<void> {
  try {
    await r2Client.send(
      new AbortMultipartUploadCommand({
        Bucket: BUCKET_NAME,
        Key: key,
        UploadId: uploadId,
      }),
    );
  } catch (err) {
    const status = (err as { $metadata?: { httpStatusCode?: number } })
      .$metadata?.httpStatusCode;
    const name = (err as { name?: string }).name;
    if (status === 404 || name === "NoSuchUpload") {
      return; // Already aborted / completed / never existed.
    }
    throw err;
  }
}
