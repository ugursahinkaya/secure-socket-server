import { IncomingMessage, createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { ChatConsumer } from "./chat-consumer.js";
import { base64ToArrayBuffer } from "@ugursahinkaya/utils";
import { SecureAuth } from "@ugursahinkaya/secure-auth";

export interface ExtWebSocket extends WebSocket {
  consumer: ChatConsumer;
}
const authProvider = process.env.AUTH_PROVIDER;
let refreshToken = process.env.REFRESH_TOKEN;
if (!authProvider) {
  throw new Error("AUTH_PROVIDER env var must be set");
}
if (!refreshToken) {
  throw new Error("REFRESH_TOKEN env var must be set");
}
export const authApi = new SecureAuth(authProvider, {
  getRefreshToken() {
    return refreshToken!;
  },
  saveRefreshToken(token) {
    refreshToken = token;
  },
  async loginOrRegister() {
    await authApi.refresh(refreshToken!);
  },
});
const server = createServer();

const wss = new WebSocketServer({ server });
const consumers = new Map<string, ChatConsumer>();
const userNames = new Map<string, string>();
wss.on("connection", async (ws: ExtWebSocket, req: IncomingMessage) => {
  const queryToken = req.url?.replace("ws", "").replaceAll("/", "");

  if (!queryToken) {
    console.log("queryToken is undefined closing socket");
    ws.close(1002, "missed queryToken"); // protocol error code
    return;
  }
  ws.consumer = consumers.get(queryToken) ?? new ChatConsumer(queryToken, ws);
  if (!ws.consumer.user?.userName) {
    await ws.consumer.init();
  }
  console.log(ws.consumer.user?.userName, "connected");

  if (
    ws.consumer.user?.userName === undefined ||
    ws.consumer.publicKey === undefined
  ) {
    console.log("Consumer is invalid. Closing socket");
    ws.close(1008, "invalid user"); // policy error code
    return;
  }
  consumers.set(queryToken, ws.consumer);
  userNames.set(ws.consumer.user?.userName, queryToken);
  ws.send(ws.consumer.publicKey);

  ws.on("pong", () => {
    ws.consumer.isAlive = true;
    ws.consumer.lastSeen = new Date();
  });

  ws.on("ping", () => {
    ws.consumer.isAlive = true;
    ws.consumer.lastSeen = new Date();
  });

  ws.on("message", async (message: Buffer) => {
    const sendUserData = ws.consumer.hasSecret === false;
    const decrypted = await ws.consumer.messageHandler(message);
    if (sendUserData) {
      if (ws.consumer.user) {
        void ws.consumer.send(ws, {
          body: ws.consumer.user,
          process: "updateUser",
          sender: "server",
        });
      }
    }
    if (decrypted && decrypted.receiver) {
      if (decrypted.receiver === "server") {
        if (decrypted.process === "ping") {
          const [ciphertext, iv] = await ws.consumer.encrypt(
            JSON.stringify({
              queryId: decrypted.queryId,
              body: {},
              sender: "server",
            })
          );
          const blob = new Blob([iv, ciphertext], { type: "text/plain" });
          void ws.consumer.setSalt(base64ToArrayBuffer(decrypted.body));
          const buffer = await blob.arrayBuffer();
          void ws.send(buffer);
        }
        return;
      }
      const receiver = userNames.get(decrypted.receiver);
      if (!receiver) {
        const [ciphertext, iv] = await ws.consumer.encrypt(
          JSON.stringify({
            error: "receiver not found",
            queryId: decrypted.queryId,
            body: { receiver: decrypted.receiver },
          })
        );
        const blob = new Blob([iv, ciphertext], { type: "text/plain" });
        ws.send(await blob.arrayBuffer());
      } else {
        const receiverConsumerObj = consumers.get(receiver);
        if (!receiverConsumerObj) {
          ws.close(1002, "invalid error");
          return;
        }
        const [ciphertext, iv] = await receiverConsumerObj.encrypt(
          JSON.stringify({
            body: decrypted.body,
            sender: ws.consumer.user?.userName,
            receiver: decrypted.receiver,
            sent: new Date(),
            process: decrypted.process,
            workerProcess: decrypted.workerProcess,
            queryId: decrypted.queryId,
          })
        );
        const blob = new Blob([iv, ciphertext], { type: "text/plain" });
        receiverConsumerObj.socket.send(await blob.arrayBuffer());
      }
    }
  });

  ws.on("error", (error: Error) => {
    console.error("WebSocket error:", error);
  });

  ws.on("close", () => {
    consumers.delete(queryToken);
    console.log("Client disconnected");
  });
});
let pingTimeout = 10;
let refreshTimeout = 100;
const interval = setInterval(() => {
  if (pingTimeout < 1) {
    //void authApi.getQueryToken();
    pingTimeout = 10;
  }
  pingTimeout--;
  if (refreshTimeout < 1) {
    //void authApi.getQueryToken();
    pingTimeout = 10;
  }
  pingTimeout--;
  wss.clients.forEach((ws: WebSocket) => {
    const extWs = ws as ExtWebSocket;
    if (!extWs.consumer.isAlive) return extWs.terminate();
    if (new Date().getTime() - extWs.consumer.lastSeen.getTime() > 5 * 1000) {
      extWs.consumer.isAlive = false; // will be true in pong event listener
      extWs.ping((err: string) => {
        if (!err) {
          return;
        }
        console.log(
          `ping error on ${extWs.consumer.user?.userName} connection : ${err}`
        );
        ws.close(1002, "ping error");
      });
    }
  });
}, 6000);

wss.on("close", () => {
  clearInterval(interval);
});

server.listen(8080, () => {
  console.log("Server is listening on port 8080");
});
