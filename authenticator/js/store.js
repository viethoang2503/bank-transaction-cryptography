// Minimal IndexedDB key-value store. CryptoKey objects are structured-cloneable,
// so non-extractable keys can be persisted without ever exposing key bytes.
const DB_NAME = "tba-authenticator";
const STORE = "kv";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(req.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export const get = (key) => run("readonly", (s) => s.get(key));
export const put = (key, value) => run("readwrite", (s) => s.put(value, key));
export const clear = () => run("readwrite", (s) => s.clear());
