import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
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

// Presigned URL expiration times
const UPLOAD_URL_EXPIRY = 60 * 60; // 1 hour for uploads
const DOWNLOAD_URL_EXPIRY = 15 * 60; // 15 minutes for downloads

export interface PresignedUploadUrl {
  url: string;
  key: string;
  expiresAt: Date;
}

export interface PresignedDownloadUrl {
  url: string;
  expiresAt: Date;
}

/**
 * Generate a presigned URL for uploading a file directly to R2.
 *
 * When `contentLength` is provided, it is baked into the signature: R2 will
 * reject any PUT whose actual body length differs, which prevents a client
 * from uploading more (or less) than the size we already accounted for in
 * the per-file / per-transfer / monthly volume limits (audit doc 25 §A.2).
 */
export async function getPresignedUploadUrl(
  key: string,
  contentType: string = "application/octet-stream",
  contentLength?: number
): Promise<PresignedUploadUrl> {
  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    ContentType: contentType,
    ContentLength: contentLength,
  });

  const url = await getSignedUrl(r2Client, command, {
    expiresIn: UPLOAD_URL_EXPIRY,
    // Without this, the SDK only signs the standard host/x-amz-* set and
    // omits content-length from SignedHeaders — meaning the constraint
    // wouldn't actually be enforced at the bucket. Force it in.
    unhoistableHeaders: new Set(["content-length"]),
  });

  const expiresAt = new Date(Date.now() + UPLOAD_URL_EXPIRY * 1000);

  return { url, key, expiresAt };
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
