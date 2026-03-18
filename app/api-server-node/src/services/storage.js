const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const STORAGE_TYPE = process.env.STORAGE_TYPE || 'local';
const UPLOADS_DIR = path.join(__dirname, '../../uploads');
const PUBLIC_UPLOADS_BASE_PATH = normalizePath(process.env.PUBLIC_UPLOADS_BASE_PATH || '/uploads');

function normalizePath(value) {
  if (!value || value === '/') {
    return '/';
  }

  return `/${value.replace(/^\/+|\/+$/g, '')}`;
}

async function uploadFile(file) {
  if (STORAGE_TYPE === 's3') {
    return uploadToS3(file);
  }

  return uploadToLocal(file);
}

function uploadToLocal(file) {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }

  const ext = path.extname(file.originalname);
  const fileName = `${uuidv4()}${ext}`;
  const filePath = path.join(UPLOADS_DIR, fileName);

  fs.writeFileSync(filePath, file.buffer);

  return `${PUBLIC_UPLOADS_BASE_PATH}/${fileName}`;
}

async function uploadToS3(file) {
  const { getS3Client } = require('../config/aws');
  const { PutObjectCommand } = require('@aws-sdk/client-s3');

  const s3 = getS3Client();
  const ext = path.extname(file.originalname);
  const key = `uploads/${uuidv4()}${ext}`;

  const command = new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: key,
    Body: file.buffer,
    ContentType: file.mimetype,
  });

  await s3.send(command);

  const region = process.env.S3_REGION || 'ap-northeast-2';
  return `https://${process.env.S3_BUCKET}.s3.${region}.amazonaws.com/${key}`;
}

async function getPresignedUrl(fileName, fileType) {
  if (STORAGE_TYPE !== 's3') {
    throw new Error('Pre-signed URLs are only supported when STORAGE_TYPE=s3');
  }

  const { getS3Client } = require('../config/aws');
  const { PutObjectCommand } = require('@aws-sdk/client-s3');
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

  const s3 = getS3Client();
  const ext = path.extname(fileName);
  const key = `uploads/${uuidv4()}${ext}`;

  const command = new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: key,
    ContentType: fileType,
  });

  const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 900 });

  const region = process.env.S3_REGION || 'ap-northeast-2';
  const fileUrl = `https://${process.env.S3_BUCKET}.s3.${region}.amazonaws.com/${key}`;

  return { uploadUrl, fileUrl };
}

async function getPresignedGetUrl(url, expiresIn = 3600) {
  if (!url) return url;

  if (url.startsWith('/')) return url;

  if (url.includes('X-Amz-Signature')) return url;

  const bucket = process.env.S3_BUCKET;
  if (!bucket || !url.includes(`${bucket}.s3`)) return url;

  const { getS3Client } = require('../config/aws');
  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

  const urlObj = new URL(url);
  const key = urlObj.pathname.startsWith('/') ? urlObj.pathname.slice(1) : urlObj.pathname;

  const s3 = getS3Client();
  const command = new GetObjectCommand({
    Bucket: bucket,
    Key: key,
  });

  return getSignedUrl(s3, command, { expiresIn });
}

module.exports = { uploadFile, getPresignedUrl, getPresignedGetUrl };
