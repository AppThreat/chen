const api = { get() {}, request() {} };
function handler(req) {
  api.get(req.query.a);
  api.request(req.query.b);
  other.exec(req.query.c);
  fetch(req.query.d);
}
module.exports = handler;
