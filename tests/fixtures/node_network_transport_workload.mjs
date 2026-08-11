import assert from "node:assert/strict";
import net from "node:net";

const requestParts = [Buffer.alloc(101, "a"), Buffer.alloc(131, "b"), Buffer.alloc(151, "c")];
const responseParts = [Buffer.alloc(173, "d"), Buffer.alloc(179, "e")];
const requestBytes = requestParts.reduce((total, part) => total + part.length, 0);
const responseBytes = responseParts.reduce((total, part) => total + part.length, 0);

const server = net.createServer((socket) => {
  let received = 0;
  socket.on("data", (chunk) => {
    received += chunk.length;
    if (received === requestBytes) {
      socket.cork();
      for (const part of responseParts) socket.write(part);
      socket.uncork();
      socket.end();
    }
  });
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});

const address = server.address();
assert.equal(typeof address, "object");
const client = net.createConnection({ host: "127.0.0.1", port: address.port });
let responseReceived = 0;
client.on("data", (chunk) => {
  responseReceived += chunk.length;
});

await new Promise((resolve, reject) => {
  client.once("error", reject);
  client.once("connect", () => {
    client.cork();
    for (const part of requestParts) client.write(part);
    client.uncork();
  });
  client.once("close", resolve);
});

assert.equal(responseReceived, responseBytes);
await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
console.log(`node-network-transport-ok sent=${requestBytes} received=${responseBytes}`);
