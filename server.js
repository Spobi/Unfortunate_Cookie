require('dotenv').config();
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;

if (!CLAUDE_API_KEY) {
    console.error('Error: CLAUDE_API_KEY not found in .env file');
    process.exit(1);
}

// Function to get the correct content type for files
function getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'text/javascript',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml'
    };
    return mimeTypes[ext] || 'text/plain';
}

const server = http.createServer((req, res) => {
    // Enable CORS so your website can talk to this server
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Handle POST requests to /fortune
    if (req.method === 'POST' && req.url === '/fortune') {
        const data = JSON.stringify({
            model: 'claude-3-haiku-20240307',
            max_tokens: 150,
            messages: [{
                role: 'user',
                content: `Generate an unfortunate cookie message (like a fortune cookie) following these rules:
                - Maximum 50 characters total
                - Don't be cryptic, be direct
                - ten percent of the time reference a date
                - ten percent of the time reference a specific location,
                - ten percent reference a first name,
                - ten percent reference an animal,
                - ten percent reference a household object,
                - ten percent reference a color,
                - ten percent reference a non-date number,
                - ten percent reference a activity or event,
                - ten percent reference a food or drink,
                - Hint at something without saying what
                - Use an indirect, cryptic tone

                Examples of good fortunes:
                - "Someone whose name starts with J is going to..."
                - "Check the expiration date on tomorrow's breakfast"
                - "Avoid blue cars on Thursday"
                - "Your third phone call next week won't be what it seems"
                - "The person sitting behind you knows something"
                Give only the fortune text, no quotes or explanation.`
            }]
        });

        const options = {
            hostname: 'api.anthropic.com',
            path: '/v1/messages',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01',
                'Content-Length': data.length
            }
        };

        const apiReq = https.request(options, (apiRes) => {
            let responseData = '';

            apiRes.on('data', (chunk) => {
                responseData += chunk;
            });

            apiRes.on('end', () => {
                try {
                    const parsed = JSON.parse(responseData);
                    const fortune = parsed.content[0].text;
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ fortune }));
                } catch (error) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to generate fortune' }));
                }
            });
        });

        apiReq.on('error', (error) => {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'API request failed' }));
        });

        apiReq.write(data);
        apiReq.end();
        return;
    }

    // Handle GET requests for static files
    if (req.method === 'GET') {
        let filePath = req.url === '/' ? '/index.html' : req.url;
        filePath = path.join(__dirname, filePath);

        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found');
                return;
            }

            const contentType = getContentType(filePath);
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(data);
        });
        return;
    }

    // All other requests
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Your website is now live!');
});