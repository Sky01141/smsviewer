// private30-relay — 暗号化済みデータだけを一時的に保管する中継サーバー。
// 中身(payload)は常に暗号文で、このサーバーは復号できない。
// ログに payload を出力しない。永続保存しない(プロセス再起動で全消去)。
import express from "express";

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

const ROOM_RE = /^[a-f0-9]{64}$/;
const MAX_TTL_MS = 31 * 60 * 1000;
const rooms = new Map(); // roomId -> { payload, exp, updatedAt }

// 簡易レート制限（IPごと・1分あたり）
const hits = new Map();
function allowed(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 60000);
  list.push(now);
  hits.set(ip, list);
  return list.length <= 120;
}
app.use((req, res, next) => {
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;
  if (!allowed(ip)) return res.status(429).json({ error: "rate_limited" });
  next();
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rooms) if (v.exp < now) rooms.delete(k);
}, 60000);

app.post("/api/push/:room", (req, res) => {
  const room = req.params.room;
  if (!ROOM_RE.test(room)) return res.status(400).json({ error: "bad_room" });
  const { payload, exp } = req.body || {};
  if (typeof payload !== "string" || payload.length === 0 || payload.length > 200000) {
    return res.status(400).json({ error: "bad_payload" });
  }
  const e = Number(exp);
  if (!Number.isFinite(e) || e <= Date.now() || e > Date.now() + MAX_TTL_MS) {
    return res.status(400).json({ error: "bad_exp" });
  }
  rooms.set(room, { payload, exp: e, updatedAt: Date.now() });
  res.json({ ok: true });
});

app.get("/api/pull/:room", (req, res) => {
  const room = req.params.room;
  if (!ROOM_RE.test(room)) return res.status(400).json({ error: "bad_room" });
  const r = rooms.get(room);
  if (!r || r.exp < Date.now()) return res.status(404).json({ error: "not_found" });
  res.json({ payload: r.payload, updatedAt: r.updatedAt, exp: r.exp });
});

// 端末側が「ロック」や「リモート終了」の際に呼び、中継上のデータを即時消去する
app.delete("/api/push/:room", (req, res) => {
  const room = req.params.room;
  if (!ROOM_RE.test(room)) return res.status(400).json({ error: "bad_room" });
  rooms.delete(room);
  res.json({ ok: true });
});

app.get("/", (req, res) => res.type("text/plain").send("private30 relay: encrypted blobs only, nothing logged"));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("private30-relay listening on", port));
