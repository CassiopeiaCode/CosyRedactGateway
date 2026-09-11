import http from "node:http";
import { Readable } from "node:stream";
import { handleRequest } from "./worker.js";

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || "127.0.0.1";

const server = http.createServer(async (req, res) => {
  try {
    const origin = `http://${req.headers.host || `${host}:${port}`}`;
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : Readable.toWeb(req);
    const request = new Request(new URL(req.url, origin), { method:req.method, headers:req.headers, body, duplex:body ? "half" : undefined });
    const response = await handleRequest(request, process.env);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (!response.body) return res.end();
    for await (const chunk of Readable.fromWeb(response.body)) res.write(chunk);
    res.end();
  } catch (e) {
    res.statusCode = 500; res.end(String(e?.stack || e));
  }
});
server.listen(port, host, () => console.log(`reduct-proxy listening on http://${host}:${port}`));
