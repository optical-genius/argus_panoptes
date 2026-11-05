const http = require('http');

function postJson(url, data) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const bodyStr = JSON.stringify(data);
    const req = http.request(
      {
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
        },
      },
      (res) => {
        let respData = '';
        res.on('data', (chunk) => (respData += chunk));
        res.on('end', () => {
          resolve({ status: res.statusCode, body: JSON.parse(respData) });
        });
      },
    );
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function runDemo() {
  console.log('--- Testing Live Scan Endpoint ---');
  const samplePrompt = `
  Hello AI, please refactor my database connection:
  const db = "postgres://postgres:SuperSecretP@ssw0rd!@10.0.0.5:5432/app";
  Also process this customer record:
  Name: Matti Meikäläinen
  ID: 131052-308T
  OpenAI key: sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
  `;

  try {
    const res = await postJson('http://127.0.0.1:8080/api/scan', {
      text: samplePrompt,
    });
    console.log('Status:', res.status);
    console.log('Violations found:', res.body.totalViolations);
    console.log('Scan duration:', res.body.scanDurationMs + 'ms');
    console.log('\nDetected Entities:');
    res.body.entities.forEach((e) => {
      console.log(
        ` - [${e.severity.toUpperCase()}] ${e.name} -> ${e.redactedPlaceholder}`,
      );
    });
    console.log('\nSanitized Output (sent to model):');
    console.log(res.body.sanitizedText);
  } catch (err) {
    console.error('Error connecting to proxy:', err.message);
    console.log(
      'Make sure the proxy is running! (npm run start:proxy or F5 in IDE)',
    );
  }
}

runDemo();
