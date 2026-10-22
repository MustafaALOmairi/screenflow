'use strict';
// تخزين بسيط في ملف JSON — مناسب لمحل أو عدة فروع.
// للتوسع الكبير يمكن استبداله بـ MySQL بنفس الدوال.
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, 'data');
const FILE = path.join(DIR, 'db.json');
fs.mkdirSync(DIR, { recursive: true });

const data = { users: [], sessions: [], screens: [], media: [] };

if (fs.existsSync(FILE)) {
  try {
    Object.assign(data, JSON.parse(fs.readFileSync(FILE, 'utf8')));
  } catch (e) {
    console.error('تعذر قراءة قاعدة البيانات data/db.json:', e.message);
    process.exit(1);
  }
}

let timer = null;
function save() {
  if (timer) return;
  timer = setTimeout(flush, 200);
}
function flush() {
  if (timer) { clearTimeout(timer); timer = null; }
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 1));
  fs.renameSync(tmp, FILE);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { flush(); } catch (e) {} process.exit(0); });
}

module.exports = { data, save, flush };
