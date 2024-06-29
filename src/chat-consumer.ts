import { SocketPayload } from "@ugursahinkaya/shared-types";
import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import { ExtWebSocket, authApi } from "./index.js";

export class ChatConsumer {
  user?: Record<string, any> & { userName: string };
  publicKey?: ArrayBuffer;
  isAlive: boolean;
  lastSeen: Date;
  hasSecret: boolean;
  promises: Promise<any>[] = [];
  crypto?: CryptoLib;
  constructor(
    public queryToken: string,
    public socket: ExtWebSocket
  ) {
    this.isAlive = true;
    this.lastSeen = new Date();
    this.hasSecret = false;
  }
  async generateKey(userName: string) {
    this.crypto = new CryptoLib();
    await this.crypto.generateKey(userName);
  }
  async messageHandler(message: Buffer) {
    this.lastSeen = new Date();
    await Promise.all(this.promises);
    if (!this.user?.userName || !this.crypto) {
      console.log("Consumer is invalid. Closing socket");
      return Promise.reject({ code: 1002, reason: "invalid error" });
    }
    if (!this.hasSecret) {
      await this.importPublicKey(message);
      return;
    } else {
      const decrypted = (await this.crypto.decryptBuffer(
        message,
        true,
        this.user.userName
      )) as unknown as SocketPayload<any>;
      return decrypted;
    }
  }
  async setSalt(salt: ArrayBufferLike) {
    if (!this.user?.userName || !this.crypto) {
      console.log("Consumer is invalid. Closing socket");
      return Promise.reject({ code: 1002, reason: "invalid error" });
    }
    await this.crypto.setSecretSalt(this.user.userName, salt);
  }
  async encrypt(message: string) {
    if (!this.user?.userName || !this.crypto) {
      console.log("Consumer is invalid. Closing socket");
      return Promise.reject({ code: 1002, reason: "invalid error" });
    }
    const res = await this.crypto.encrypt(message, this.user.userName);
    return res;
  }

  async send(ws: ExtWebSocket, message: Record<string, any>) {
    const [ciphertext, iv] = await this.encrypt(JSON.stringify(message));
    const blob = new Blob([iv, ciphertext], { type: "text/plain" });
    const buffer = await blob.arrayBuffer();
    void ws.send(buffer);
  }

  async importPublicKey(publicKey: Buffer) {
    const promise = new Promise<void>((resolve, reject) => {
      if (!this.user?.userName || !this.crypto) {
        reject({ code: 1002, reason: "invalid error" });
        return;
      }
      this.crypto
        .importPublicKey(publicKey, this.user.userName)
        .then(() => {
          this.hasSecret = true;
          resolve();
        })
        .catch(() => {
          reject({ code: 1002, reason: "invalid key" });
        });
    });
    this.promises.push(promise);
    return promise;
  }

  async init() {
    await Promise.all(this.promises);
    const whoIsRes = (await authApi.whoIs(this.queryToken)) as unknown as {
      userName: string;
      error?: string;
    };
    if (whoIsRes.error) {
      this.socket.close(1002, "invalid token");
      return;
    }
    const userName = whoIsRes.userName;
    if (!userName) {
      return;
    }
    this.user = whoIsRes;
    await this.generateKey(userName);
    this.publicKey = await this.crypto?.exportKey(userName);
  }
}
