require('dotenv').config();
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;

// Rate limiting - track requests per IP address
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_WINDOW = 5; // Max 10 requests per minute per IP
const MAX_FORTUNE_LENGTH = 55;

// Security: Validate IP address format
function isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip) || ip === '::1' || ip === 'unknown';
}

function isRateLimited(req) { // CHANGED: now takes 'req' instead of 'ip'
    // More secure IP extraction - NEW SECTION
    let ip = req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress ||
             'unknown';
    
    // Handle multiple IPs in x-forwarded-for (take the first one) - NEW
    if (ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    
    // Security: Validate IP format - NEW
    if (!isValidIP(ip)) {
        console.log(`Invalid IP format detected: ${ip}`);
        return true; // Block invalid IPs
    }

    const now = Date.now();
    const userRequests = requestCounts.get(ip) || [];
    
    // Remove old requests outside the time window
    const recentRequests = userRequests.filter(time => now - time < RATE_LIMIT_WINDOW);
    
    // Update the map with recent requests
    requestCounts.set(ip, recentRequests);
    
    // Check if user has exceeded the limit
    if (recentRequests.length >= MAX_REQUESTS_PER_WINDOW) {
        return true; // Rate limited
    }
    
    // Add this request to the count
    recentRequests.push(now);
    requestCounts.set(ip, recentRequests);
    
    return false; // Not rate limited
}

// Security: Input validation for fortune requests
function validateFortuneRequest(req) {
    // Check content type
    if (req.headers['content-type'] !== 'application/json') {
        return false;
    }
    return true;
}

// Security: Sanitize fortune text
function sanitizeFortune(fortune) {
    if (!fortune || typeof fortune !== 'string') {
        return 'The spirits are silent today...';
    }
    
    // Remove any potential HTML/script content
    let sanitized = fortune
        .replace(/<[^>]*>/g, '') // Remove HTML tags
        .replace(/javascript:/gi, '') // Remove javascript: protocols
        .replace(/on\w+\s*=/gi, '') // Remove event handlers
        .trim();
    
    // Limit length
    if (sanitized.length > MAX_FORTUNE_LENGTH) {
        sanitized = sanitized.substring(0, MAX_FORTUNE_LENGTH).trim() + '...';
    }
    
    return sanitized || 'The spirits are silent today...';
}

if (!CLAUDE_API_KEY) {
    console.error('Error: CLAUDE_API_KEY not found in .env file');
    process.exit(1);
}

// Function to get the correct content type for files
function getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
        '.html': 'text/html; charset=UTF-8',
        '.css': 'text/css; charset=UTF-8',
        '.js': 'text/javascript; charset=UTF-8',
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
    res.setHeader('X-Content-Type-Options', 'nosniff');
   res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");

    const allowedOrigins = [
        'https://unfortunatecookie.club',
        'http://localhost:3000',
        'http://127.0.0.1:3000'
    ];

    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    if (!['GET', 'POST'].includes(req.method)) {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
}

    // Handle POST requests to /fortune
    if (req.method === 'POST' && req.url === '/fortune') {
        
        
if (isRateLimited(req)) {
    res.writeHead(429, { 
        'Content-Type': 'application/json',
        'Retry-After': '60'
    });
    res.end(JSON.stringify({ 
        error: 'Too many requests. Please wait a moment before trying again.' 
    }));
    return;
}

// Security: Validate request format
if (!validateFortuneRequest(req)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid request format' }));
    return;
}

// Security: Parse request body with size limit
let body = '';
const maxBodySize = 1024; // 1KB limit

req.on('data', (chunk) => {
    body += chunk;
    if (body.length > maxBodySize) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Request too large' }));
        return;
    }
});

req.on('end', () => {
    // Generate a unique request ID for logging
    const requestId = crypto.randomBytes(8).toString('hex');
    console.log(`Fortune request ${requestId} received`);

    const data = JSON.stringify({

            model: 'claude-3-haiku-20240307',
            max_tokens: 150,
            messages: [{
                role: 'user',
                content: `You are generating fortune ${Math.floor(Math.random() * 10069)} Generate an unfortunate cookie message (like a fortune cookie) following these rules:
                - Maximum 50 characters total
                - Don't be cryptic, be direct
                - Don't say the word Beware
                - Hint at something without saying it,
                - Only include one specific detail from the list below:
                    - ten percent of the time reference a date,
                    - ten percent of the time reference a specific location,
                    - ten percent reference a first name,
                    - ten percent reference a household object,
                    - ten percent reference a color,
                    - ten percent reference a non-date number,
                    - ten percent reference a activity or event,
                    - ten percent reference a food or drink,

                    Try to avoid saying the same thing over and over again. The best way to do this is by being random. Don't say too many colors. Don't say too many animals. Don't say too many etc...

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
            timeout: 10000, // 10 second timeout
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01',
                'Content-Length': data.length,
                'User-Agent': 'UnfortunateCookie/1.0'
            }
        };

const apiReq = https.request(options, (apiRes) => {
    let responseData = '';
    const maxResponseSize = 5120; // 5KB limit

    apiRes.on('data', (chunk) => {
        responseData += chunk;
        if (responseData.length > maxResponseSize) {
            console.log(`Request ${requestId}: Response too large`);
            apiReq.destroy();
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Response too large' }));
            return;
        }
    });

    apiRes.on('end', () => {
        try {
            const parsed = JSON.parse(responseData);
            
            // Security: Validate API response structure
            if (!parsed.content || !Array.isArray(parsed.content) || !parsed.content[0] || !parsed.content[0].text) {
                console.log(`Request ${requestId}: Invalid API response structure`);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid response from fortune service' }));
                return;
            }
            
            const rawFortune = parsed.content[0].text;
            const sanitizedFortune = sanitizeFortune(rawFortune);
            
            console.log(`Request ${requestId}: Fortune generated successfully`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ fortune: sanitizedFortune }));
            
        } catch (error) {
            console.log(`Request ${requestId}: JSON parse error`);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to process fortune' }));
        }
    });
});

        apiReq.on('timeout', () => {
            console.log(`Request ${requestId}: API timeout`);
            apiReq.destroy();
            res.writeHead(504, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Fortune service unavailable' }));
        });

        apiReq.on('error', (error) => {
            console.log(`Request ${requestId}: API error`);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Fortune service unavailable' }));
        });

        apiReq.setTimeout(10000); // Set timeout
        apiReq.write(data);
        apiReq.end();
    });
        return;
    }

// Handle GET requests for static files
if (req.method === 'GET') {
    let filePath = req.url === '/' ? '/index.html' : req.url;
    
    // Security: Prevent path traversal attacks
    if (filePath.includes('..') || filePath.includes('//') || filePath.includes('\\')) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request');
        return;
    }
    
    filePath = path.join(__dirname, filePath);
    
    // Security: Ensure file is within the server directory
    if (!filePath.startsWith(__dirname)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            // Don't expose detailed error information
            if (err.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found');
            } else {
                console.log(`File read error: ${err.code}`);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
            }
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