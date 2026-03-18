/**
 * S3 이미지 URL → Pre-signed URL 변환 미들웨어
 * - S3 모드에서 응답의 이미지 URL을 Pre-signed URL로 변환
 * - 로컬 모드에서는 패스스루
 */

const presignUrlsMiddleware = (req, res, next) => {
  // 로컬 모드에서는 변환 없이 패스
  if (process.env.STORAGE_TYPE !== 's3') {
    return next();
  }

  // S3 모드: 응답 JSON의 이미지 URL을 Pre-signed URL로 변환
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    // TODO: S3 URL을 Pre-signed URL로 변환하는 로직 구현
    originalJson(body);
  };

  next();
};

module.exports = presignUrlsMiddleware;
