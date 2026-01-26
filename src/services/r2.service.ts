import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
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
const DOWNLOAD_URL_EXPIRY = 60 * 60; // 1 hour for downloads

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
 * Generate a presigned URL for uploading a file directly to R2
 */
export async function getPresignedUploadUrl(
  key: string,
  contentType: string = "application/octet-stream"
): Promise<PresignedUploadUrl> {
  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    ContentType: contentType,
  });

  const url = await getSignedUrl(r2Client, command, {
    expiresIn: UPLOAD_URL_EXPIRY,
  });

  const expiresAt = new Date(Date.now() + UPLOAD_URL_EXPIRY * 1000);

  return { url, key, expiresAt };
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
