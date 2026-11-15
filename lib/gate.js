// Acceso protegido: el contenido está cifrado (AES-256-GCM). La clave se deriva de la contraseña (PBKDF2).
const SALT = 'u4mHbbYQF3xo+l6/l7CmkA==';
const ITER = 310000;
const K = 'ferruz_xr_key';

const b64 = {
  enc: (u8) => btoa(String.fromCharCode(...u8)),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function derive(password) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64.dec(SALT), iterations: ITER }, base, 256);
  return new Uint8Array(bits);
}
function storedKey() {
  try { return sessionStorage.getItem(K) || localStorage.getItem(K); } catch (e) { return null; }
}
function storeKey(raw, remember) {
  const s = b64.enc(raw);
  try { sessionStorage.setItem(K, s); if (remember) localStorage.setItem(K, s); } catch (e) {}
}
export function forget() {
  try { sessionStorage.removeItem(K); localStorage.removeItem(K); } catch (e) {}
}
async function cryptoKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
}
// Formato: [12 bytes IV][datos cifrados + etiqueta GCM]
export async function decryptBuffer(buf, rawKey) {
  const raw = rawKey || b64.dec(storedKey() || '');
  const u8 = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, await cryptoKey(raw), u8.slice(12));
}
export async function fetchDecrypted(url, onProgress) {
  const res = await fetch(url);
  if (!res.ok) throw new Error('No se encontró ' + url);
  const total = +res.headers.get('content-length') || 0;
  const reader = res.body.getReader();
  const chunks = []; let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); got += value.length;
    if (onProgress) onProgress(got, total);
  }
  const all = new Uint8Array(got); let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.length; }
  return decryptBuffer(all.buffer);
}

// Pide la contraseña si hace falta. checkUrl: un archivo cifrado con el que validar la clave.
export async function ensureKey(checkUrl) {
  const enc = await (await fetch(checkUrl)).arrayBuffer();
  const saved = storedKey();
  if (saved) {
    const raw = b64.dec(saved);
    try { await decryptBuffer(enc, raw); return { raw, enc }; } catch (e) { forget(); }
  }
  return new Promise((resolve) => {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'position:fixed;inset:0;z-index:9999;background:#16161a;overflow:auto';
    wrap.innerHTML = `
    <form id="gf" style="max-width:360px;margin:16vh auto;padding:32px;background:#222228;border-radius:14px;color:#eee;font-family:system-ui,Segoe UI,Arial,sans-serif;box-shadow:0 10px 40px rgba(0,0,0,.4)">
      <div style="color:#e30613;font-weight:800;font-size:22px;letter-spacing:.5px">FERRUZ</div>
      <div style="font-size:14px;opacity:.75;margin:4px 0 22px">Acceso restringido · Catálogo y visor XR</div>
      <input id="gp" type="password" placeholder="Contraseña" autocomplete="current-password" autofocus
        style="width:100%;box-sizing:border-box;padding:13px 14px;border-radius:9px;border:1px solid #444;background:#15151a;color:#fff;font-size:16px">
      <label style="display:flex;gap:8px;align-items:center;font-size:14px;margin:14px 0 18px;opacity:.85">
        <input id="gr" type="checkbox"> Recordar en este dispositivo</label>
      <button style="width:100%;padding:13px;border:0;border-radius:9px;background:#e30613;color:#fff;font-size:16px;font-weight:600;cursor:pointer">Entrar</button>
      <div id="gm" style="min-height:20px;margin-top:12px;font-size:14px"></div>
    </form>`;
    document.body.appendChild(wrap);
    wrap.querySelector('#gf').onsubmit = async (e) => {
      e.preventDefault();
      const m = wrap.querySelector('#gm');
      m.style.color = '#bbb'; m.textContent = 'Comprobando…';
      const raw = await derive(wrap.querySelector('#gp').value);
      try {
        await decryptBuffer(enc, raw);
        storeKey(raw, wrap.querySelector('#gr').checked);
        wrap.remove();
        resolve({ raw, enc });
      } catch (err) { m.style.color = '#ff6b73'; m.textContent = 'Contraseña incorrecta'; }
    };
  });
}

// Abre una página entera cifrada (sin módulos ni import maps dentro).
export async function openProtected(encUrl) {
  const { raw, enc } = await ensureKey(encUrl);
  const html = new TextDecoder().decode(await decryptBuffer(enc, raw));
  document.open(); document.write(html); document.close();
}
