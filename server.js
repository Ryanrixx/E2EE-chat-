// server.js
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));

const users = {}; // username -> { socketId, publicKeyPem }

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('register', ({ username, publicKeyPem }) => {
    users[username] = { socketId: socket.id, publicKeyPem };
    console.log(`Registered ${username}`);
    io.emit('user_list', Object.keys(users));
  });

  socket.on('request_pub', ({ username }) => {
    const user = users[username];
    if (user) {
      socket.emit('public_key', { username, publicKeyPem: user.publicKeyPem });
    }
  });

  socket.on('message', ({ from, to, payload }) => {
    const recipient = users[to];

    if (recipient) {
      io.to(recipient.socketId).emit('message', { from, payload });
    }

    const sender = users[from];
    if (!sender) return;

    try {
      const ackText = `ACK from Server: Delivered to ${to} (${new Date().toISOString()})`;

      const aesKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
      let encrypted = cipher.update(Buffer.from(ackText, 'utf8'));
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const tag = cipher.getAuthTag();

      const encryptedAesKey = crypto.publicEncrypt(
        {
          key: sender.publicKeyPem,
          oaepHash: 'sha256'
        },
        aesKey
      );

      const ackPayload = {
        encryptedKey: encryptedAesKey.toString('base64'),
        iv: iv.toString('base64'),
        ciphertext: encrypted.toString('base64'),
        tag: tag.toString('base64')
      };

      io.to(sender.socketId).emit('ack', ackPayload);
    } catch (err) {
      console.error('ACK encryption failed:', err);
    }
  });

  socket.on('disconnect', () => {
    for (const u in users) {
      if (users[u].socketId === socket.id) {
        delete users[u];
      }
    }
    io.emit('user_list', Object.keys(users));
  });
});

server.listen(3000, () => console.log('✅ Server running at http://localhost:3000'));
