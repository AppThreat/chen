import http from 'http';
import fs from 'fs';
import path from 'path';
import got from 'got';
import { promisify } from 'util';
import { exec as run, execFile } from 'child_process';
const cp = require('child_process');
const { execSync: shell } = require('child_process');
const axios = require('axios');
const pexec = promisify(run);

http.createServer(async (req, res) => {
  run('ls ' + req.query.dir);
  cp.exec('cat ' + req.body.file);
  shell('echo ' + req.headers.host);
  execFile(req.query.bin, []);
  await pexec('wc ' + req.query.name);
  fs.readFile(req.params.p, () => {});
  const safe = path.basename(req.query.f);
  fs.writeFile(safe, req.body.data, () => {});
  const upstream = await got(req.query.url);
  await axios.get(req.query.target);
  fs.promises.readFile(req.query.q);
  res.end(upstream.body);
}).listen(3000);
