import { IncomingMessage, Server, ServerResponse, createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { ChatConsumer } from "./chat-consumer.js";
import { base64ToArrayBuffer } from "@ugursahinkaya/utils";
import { SecureAuth } from "@ugursahinkaya/secure-auth";
import { LogLevel } from "@ugursahinkaya/shared-types";
import { SecureSocketPlugin } from "./fastify-plugin.js";
export interface ExtWebSocket extends WebSocket {
  consumer: ChatConsumer;
}
export class SecureSocket {
  consumers = new Map<string, ChatConsumer>();
  usernames = new Map<string, string>();
  server?: Server<typeof IncomingMessage, typeof ServerResponse>;
  wss?: WebSocketServer;
  authApi?: SecureAuth<any>;
  authProvider = process.env.AUTH_PROVIDER;
  refreshToken = process.env.REFRESH_TOKEN;
  port = process.env.PORT;
  whoIs: (queryToken: string) => Promise<{ username?: string; error?: string }>;
  constructor(args: {
    authProvider?: string;
    whoIs?: (
      queryToken: string
    ) => Promise<{ username?: string; error?: string }>;
    logLevel?: LogLevel;
  }) {
    if (!this.refreshToken) {
      throw new Error("REFRESH_TOKEN env var must be set");
    }
    if (args.authProvider) {
      this.authProvider = args.authProvider;
    }
    if (this.authProvider) {
      const loginOrRegister = async () => {
        await this.authApi?.refresh(this.refreshToken!);
      };
      const getRefreshToken = () => {
        return this.refreshToken!;
      };
      const saveRefreshToken = (token: string) => {
        this.refreshToken = token;
      };
      this.authApi = new SecureAuth(
        this.authProvider,
        {
          getRefreshToken,
          saveRefreshToken,
          loginOrRegister,
        },
        args.logLevel ?? "error"
      );
      this.whoIs = this.authApi.whoIs;
    }
    if (!args.whoIs ?? !this.authApi?.whoIs) {
      throw new Error("Provide whoIs fn or authProvider url()");
    }
    this.whoIs = args.whoIs ?? this.authApi?.whoIs;
  }
  init(port?: number) {
    if (port) {
      this.server = createServer();
      this.server.listen(port, () => {
        console.log("Server is listening on port 8080");
      });
      this.wss = new WebSocketServer({ server: this.server });
    } else {
      this.wss = new WebSocketServer({ noServer: true });
    }

    this.wss.on(
      "connection",
      async (ws: ExtWebSocket, req: IncomingMessage) => {
        const queryToken = req.url?.replace("ws", "").replaceAll("/", "");

        if (!queryToken) {
          console.log("queryToken is undefined closing socket");
          ws.close(1002, "missed queryToken"); // protocol error code
          return;
        }
        ws.consumer =
          this.consumers.get(queryToken) ??
          new ChatConsumer(queryToken, ws, this.whoIs);
        if (!ws.consumer.user?.username) {
          await ws.consumer.init();
        }
        console.log(ws.consumer.user?.username, "connected");

        if (ws.consumer.user?.username === undefined) {
          console.log(
            "Consumer is invalid. Closing socket",
            ws.consumer.user?.username
          );
          ws.close(1008, "invalid user"); // policy error code
          return false;
        }
        this.consumers.set(queryToken, ws.consumer);
        this.usernames.set(ws.consumer.user?.username, queryToken);
        ws.send(ws.consumer.publicKey!);

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
            const receiver = this.usernames.get(decrypted.receiver);
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
              const receiverConsumerObj = this.consumers.get(receiver);
              if (!receiverConsumerObj) {
                ws.close(1002, "invalid error");
                return;
              }
              const [ciphertext, iv] = await receiverConsumerObj.encrypt(
                JSON.stringify({
                  body: decrypted.body,
                  sender: ws.consumer.user?.username,
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
          this.consumers.delete(queryToken);
          console.log("Client disconnected");
        });
        return true;
      }
    );
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
      this.wss?.clients.forEach((ws: WebSocket) => {
        const extWs = ws as ExtWebSocket;
        if (!extWs.consumer.isAlive) return extWs.terminate();
        if (
          new Date().getTime() - extWs.consumer.lastSeen.getTime() >
          5 * 1000
        ) {
          extWs.consumer.isAlive = false; // will be true in pong event listener
          extWs.ping((err: string) => {
            if (!err) {
              return;
            }
            console.log(
              `ping error on ${extWs.consumer.user?.username} connection : ${err}`
            );
            ws.close(1002, "ping error");
          });
        }
      });
    }, 6000);

    this.wss.on("close", () => {
      clearInterval(interval);
    });
    return this.wss;
  }
}
export { SecureSocketPlugin };
