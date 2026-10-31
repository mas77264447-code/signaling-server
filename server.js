const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocketServer({ port: PORT });
const clients = new Map(); // deviceId -> WebSocket

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    switch (msg.type) {
      case 'register': {
        myId = String(msg.id);
        clients.set(myId, ws);
        ws.send(JSON.stringify({ type: 'registered', id: myId }));
        break;
      }
      case 'signal': {
        const target = clients.get(String(msg.to));
        if (target && target.readyState === 1) {
          target.send(JSON.stringify({ type: 'signal', from: myId, data: msg.data }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'الجهاز غير متصل' }));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (myId && clients.get(myId) === ws) {
      clients.delete(myId);
    }
  });
});

console.log(`Signaling server running on port ${PORT}`);
