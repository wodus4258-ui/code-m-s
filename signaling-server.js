/**
 * code-mail 시그널링 서버 (최소 구현)
 * ------------------------------------------------------
 * 역할: 두 클라이언트가 서로의 SDP(offer/answer)와 ICE candidate를
 *       교환할 수 있도록 "룸" 단위로 메시지를 중계만 함.
 *       실제 텍스트/파일 데이터는 이 서버를 거치지 않고,
 *       핸드셰이크 완료 후 RTCDataChannel로 P2P 직접 전송됨.
 *
 * 설치:
 *   npm init -y
 *   npm install ws
 *
 * 실행:
 *   node signaling-server.js
 *   (기본 포트 8080, 환경변수 PORT로 변경 가능)
 *
 * 배포:
 *   두 사용자가 서로 다른 네트워크(가정용 와이파이, LTE 등)에 있다면
 *   이 서버가 공인 인터넷에서 접근 가능해야 함.
 *   - Render / Railway / Fly.io 같은 무료 티어에 배포하거나
 *   - 자체 VPS에 두고 TLS(wss://)를 적용해서 사용 권장
 *   - 같은 로컬 네트워크(LAN) 테스트라면 PC의 사설 IP로도 충분함
 *     (예: ws://192.168.0.10:8080)
 *
 * 클라이언트(code-mail.html)의 "고급 설정 > 시그널링 서버 주소"에
 * 이 서버의 접속 주소(ws:// 또는 wss://)를 입력하면 됨.
 */

const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });

// roomId -> Set<WebSocket>
const rooms = new Map();

function broadcastToRoom(roomId, senderWs, payload) {
  const set = rooms.get(roomId);
  if (!set) return;
  const msg = JSON.stringify(payload);
  for (const peer of set) {
    if (peer !== senderWs && peer.readyState === WebSocket.OPEN) {
      peer.send(msg);
    }
  }
}

wss.on('connection', (ws) => {
  ws.room = null;

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      return; // 잘못된 형식은 무시
    }

    // 1) 룸 참가
    if (data.type === 'join') {
      const roomId = data.room;
      if (!roomId) return;

      if (!rooms.has(roomId)) rooms.set(roomId, new Set());
      const set = rooms.get(roomId);

      if (set.size >= 2) {
        ws.send(JSON.stringify({ type: 'room-full' }));
        return;
      }

      ws.room = roomId;
      set.add(ws);

      // 이미 있던 상대에게 알림
      broadcastToRoom(roomId, ws, { type: 'peer-joined' });

      // 두 명이 다 모이면 양쪽 모두에게 협상 시작 신호
      if (set.size === 2) {
        for (const peer of set) {
          peer.send(JSON.stringify({ type: 'ready' }));
        }
      }
      return;
    }

    // 2) offer / answer / ice-candidate 중계
    if (['offer', 'answer', 'ice'].includes(data.type)) {
      if (!ws.room) return;
      broadcastToRoom(ws.room, ws, data);
      return;
    }
  });

  ws.on('close', () => {
    if (!ws.room) return;
    const set = rooms.get(ws.room);
    if (!set) return;
    set.delete(ws);
    broadcastToRoom(ws.room, ws, { type: 'peer-left' });
    if (set.size === 0) rooms.delete(ws.room);
  });
});

console.log('code-mail signaling server listening on port ' + PORT);
