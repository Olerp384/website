const http = require('http');
const os = require('os');

const port = process.env.PORT || 3000;

const page = (containerId) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Container ID</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #0d1117;
      --fg: #e6edf3;
      --accent: #60a5fa;
      --card: #161b22;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at 20% 20%, #111827, #0d1117 50%), radial-gradient(circle at 80% 80%, #0f172a, #0d1117 45%);
      color: var(--fg);
      font-family: "SF Mono", "Cascadia Code", "Roboto Mono", Menlo, Monaco, Consolas, monospace;
    }
    .card {
      background: var(--card);
      border: 1px solid rgba(96, 165, 250, 0.25);
      border-radius: 12px;
      padding: 32px 36px;
      text-align: center;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
      max-width: 520px;
      width: 90vw;
      animation: float 6s ease-in-out infinite;
    }
    h1 { margin: 0 0 12px; font-size: 28px; letter-spacing: 0.02em; }
    p { margin: 0; color: #9fb3c8; }
    code {
      display: inline-block;
      margin-top: 14px;
      padding: 10px 14px;
      background: #0b1220;
      border: 1px solid rgba(96, 165, 250, 0.25);
      border-radius: 8px;
      font-size: 18px;
      letter-spacing: 0.04em;
      color: var(--accent);
    }
    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-6px); }
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Container Identifier</h1>
    <p>The container running this site reports the following ID:</p>
    <code>${containerId}</code>
  </main>
</body>
</html>`;

const server = http.createServer((req, res) => {
  // Always respond with the same page; small site doesn't need routing.
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(page(os.hostname()));
});

server.listen(port, () => {
  // Log to help diagnose container startup.
  console.log(`Container ID site listening on port ${port}`);
});
