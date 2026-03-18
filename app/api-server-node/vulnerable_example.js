/**
 * 보안 취약점 테스트용 코드 (SAST 탐지 대상)
 * - 실제 서비스에서 사용 금지
 * - SecureFlow 파이프라인 검증 목적
 */

const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const router = express.Router();

// [SAST] 하드코딩된 시크릿
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const API_KEY = "sk-1234567890abcdef";

// [SAST] SQL Injection
router.get('/users/search', (req, res) => {
  const username = req.query.username;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.all(query, (err, rows) => {
    res.json(rows);
  });
});

// [SAST] Command Injection
router.get('/system/run', (req, res) => {
  const cmd = req.query.cmd;
  const output = execSync(cmd).toString();
  res.json({ output });
});

// [SAST] Path Traversal
router.get('/files/read', (req, res) => {
  const filepath = req.query.path;
  const content = fs.readFileSync(filepath, 'utf8');
  res.json({ content });
});

// [SAST] XSS
router.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Welcome ${name}</h1>`);
});

// [SAST] 취약한 해시
router.post('/auth/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ hash });
});

// [SAST] eval 사용
router.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// [SAST] 안전하지 않은 정규식 (ReDoS)
router.post('/validate', (req, res) => {
  const regex = /^(a+)+$/;
  const match = regex.test(req.body.input);
  res.json({ valid: match });
});

module.exports = router;
