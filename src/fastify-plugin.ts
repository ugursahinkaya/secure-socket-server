import { LogLevel } from "@ugursahinkaya/shared-types";
import { FastifyInstance } from "fastify";
import { SecureSocket } from "src";

export function SecureSocketPlugin(
  fastify: FastifyInstance,
  options: {
    logLevel?: LogLevel;
  },
  done: Function
) {
  const secureSocket = new SecureSocket({
    whoIs: (queryToken) => {
      return Promise.resolve({ username: queryToken });
    },
    logLevel: options.logLevel,
  });
  fastify.server.on("upgrade", async (request, socket, head) => {
    if (!request.url) {
      socket.destroy();
      return;
    }
    console.log("upgrade", request.url);
    const regex = /^\/ws\/.+$/;

    if (regex.test(request.url) && (await secureSocket.init())) {
      console.log("handling socket");
      secureSocket.wss?.handleUpgrade(request, socket, head, (ws) => {
        secureSocket.wss?.emit("connection", ws, request);
      });
    } else {
      console.log("destroying socket");
      socket.destroy(); // Geçersiz istekleri yok say
    }
  });
  done();
}
