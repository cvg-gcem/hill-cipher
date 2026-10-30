/* ============================================================
   Hill Cipher Cryptography Dashboard
   Pure vanilla JavaScript — every result is computed live.
   Supports 2x2, 3x3, 4x4 and 5x5 key matrices.
   ============================================================ */
'use strict';

/* ============================================================
   1. CORE HILL CIPHER MATHEMATICS
   ============================================================ */
const MOD = 26;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CELL_TAGS = 'abcdefghijklmnopqrstuvwxy'.split('');

/** Euclidean modulus (always 0..m-1). */
const mod = (a, m = MOD) => ((a % m) + m) % m;

/** Greatest common divisor. */
function gcd(a, b) {
  a = Math.abs(a);
  b = Math.abs(b);
  while (b) { const t = b; b = a % b; a = t; }
  return a;
}

/** Modular multiplicative inverse via the extended Euclidean algorithm. */
function modInverse(a, m = MOD) {
  let oldR = mod(a, m), r = m;
  let oldS = 1, s = 0;
  while (r !== 0) {
    const q = Math.floor(oldR / r);
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1) return null;          // not invertible modulo m
  return mod(oldS, m);
}

/** Sub-matrix with row i and column j removed. */
function minorOf(M, i, j) {
  return M.filter((_, r) => r !== i).map(row => row.filter((_, c) => c !== j));
}

/** Exact integer determinant (Laplace expansion — precise for n <= 5). */
function determinant(M) {
  const n = M.length;
  if (n === 1) return M[0][0];
  if (n === 2) return M[0][0] * M[1][1] - M[0][1] * M[1][0];
  let d = 0;
  for (let j = 0; j < n; j++) {
    if (M[0][j] === 0) continue;
    d += (j % 2 ? -1 : 1) * M[0][j] * determinant(minorOf(M, 0, j));
  }
  return d;
}

/** Adjugate (classical adjoint) = transpose of the cofactor matrix. */
function adjugate(M) {
  const n = M.length;
  const adj = Array.from({ length: n }, () => Array(n).fill(0));
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const cof = ((i + j) % 2 ? -1 : 1) * determinant(minorOf(M, j, i));
      adj[i][j] = cof;
    }
  }
  return adj;
}

/** K * v (matrix x column vector), element-wise modulo 26. */
function matVecMod(M, v) {
  return M.map(row => {
    let s = 0;
    for (let j = 0; j < row.length; j++) s += row[j] * v[j];
    return mod(s);
  });
}

/**
 * Full key analysis: determinant, gcd test and the modular inverse matrix
 * using the adjugate/determinant method: K^-1 = det^-1 * adj(K)  (mod 26)
 */
function analyzeKey(rawMatrix) {
  const K = rawMatrix.map(r => r.map(v => mod(v)));   // canonical 0..25
  const det = determinant(K);
  const detMod = mod(det);
  const g = gcd(detMod, MOD);
  if (g !== 1) {
    return { ok: false, K, det, detMod, gcd: g, detInverse: null, inv: null };
  }
  const detInverse = modInverse(detMod);
  const adj = adjugate(K);
  const inv = adj.map(r => r.map(v => mod(v * detInverse)));
  return { ok: true, K, det, detMod, gcd: g, detInverse, inv };
}

/* ============================================================
   2. EXAMPLE DATA (keys are verified, results are computed live)
   ============================================================ */
const EXAMPLES = {
  2: { key: [3, 3, 2, 5], plaintext: 'HI' },
  3: { key: [6, 24, 1, 13, 16, 10, 20, 17, 15], plaintext: 'ATTACKATDAWN' },
  4: { key: [11, 3, 5, 7, 2, 13, 4, 6, 9, 1, 17, 8, 5, 12, 6, 19], plaintext: 'CYBERSECURITY' },
  5: { key: [3, 5, 22, 1, 6, 24, 11, 21, 12, 19, 19, 7, 23, 21, 19, 14, 17, 14, 23, 19, 22, 21, 7, 5, 7],
       plaintext: 'MATRIXBASEDCRYPTO' }
};

const DEFAULTS = { size: 2, key: [3, 3, 2, 5], plaintext: 'HELLOWORLD', ciphertext: '' };

const ENC_FLOW = ['Plaintext', 'A = 0 … Z = 25 Conversion', 'Block Formation', 'Key Matrix',
                  'Matrix Multiplication', 'Modulo 26', 'Ciphertext'];
const DEC_FLOW = ['Ciphertext', 'Numeric Conversion', 'Inverse Key Matrix',
                  'Matrix Multiplication', 'Modulo 26', 'Recovered Plaintext'];

/* ============================================================
   3. STATE + DOM REFERENCES
   ============================================================ */
const state = {
  size: 2,
  key: null,            // result of analyzeKey / malformed marker
  plainPreview: null,   // processed/padded/blocks of the plaintext
  cipherClean: '',      // cleaned ciphertext input
  operation: '—',
  ranEnc: false,
  ranDec: false,
  lastCipher: '',
  lastEncPadded: ''
};

const $ = id => document.getElementById(id);
const sizeSelect   = $('matrixSize');
const keyMatrixEl  = $('keyMatrix');
const plaintextEl  = $('plaintext');
const ciphertextEl = $('ciphertext');

const esc = s => String(s).replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ============================================================
   4. ALERTS / SMALL HELPERS
   ============================================================ */
function setAlert(el, type, title, message) {
  el.hidden = false;
  el.className = 'alert ' + type;
  el.innerHTML = `<div><strong>${esc(title)}</strong>${message ? esc(message) : ''}</div>`;
}
function clearAlert(el) { el.hidden = true; el.innerHTML = ''; }

/** Read-only matrix / vector rendering. */
function matrixHTML(mat, tone = '') {
  const cols = mat[0].length;
  let cells = '';
  for (const row of mat) for (const v of row) cells += `<span class="mval ${tone}">${v}</span>`;
  return `<span class="mview ${tone}"><span class="mgrid" style="--mc:${cols}">${cells}</span></span>`;
}
const vectorOf = arr => arr.map(v => [v]);

/* ============================================================
   5. KEY MATRIX EDITOR
   ============================================================ */
function buildMatrix(values) {
  const n = state.size;
  const grid = document.createElement('div');
  grid.className = 'matrix-grid';
  grid.style.setProperty('--n', n);
  for (let i = 0; i < n * n; i++) {
    const cell = document.createElement('div');
    cell.className = 'cell';
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = CELL_TAGS[i] || (i + 1);
    const input = document.createElement('input');
    input.type = 'text';
    input.inputMode = 'numeric';
    input.className = 'cell-input';
    input.maxLength = 7;
    input.value = values[i] !== undefined ? String(values[i]) : '';
    input.setAttribute('aria-label', `Key matrix row ${Math.floor(i / n) + 1} column ${(i % n) + 1}`);
    cell.append(tag, input);
    grid.appendChild(cell);
  }
  keyMatrixEl.innerHTML = '';
  keyMatrixEl.appendChild(grid);
  $('keyDims').textContent = `${n} × ${n}`;

  grid.addEventListener('input', () => refresh());
}

/** Parse the editable grid. Returns {ok,error} or {ok,matrix}. */
function readKey() {
  const n = state.size;
  const inputs = [...keyMatrixEl.querySelectorAll('input.cell-input')];
  const flat = [];
  let error = null;

  inputs.forEach((inp, i) => {
    const raw = inp.value.trim();
    inp.classList.remove('bad');
    const row = Math.floor(i / n) + 1, col = (i % n) + 1;
    if (raw === '') {
      inp.classList.add('bad');
      error = error || `Key matrix cannot be empty — row ${row}, column ${col} is blank. Fill every cell with an integer.`;
      flat.push(null);
    } else if (!/^-?\d{1,6}$/.test(raw)) {
      inp.classList.add('bad');
      error = error || `Non-numeric matrix value "${raw}" in row ${row}, column ${col}. Enter an integer (for example 7, 13 or -4).`;
      flat.push(null);
    } else {
      flat.push(Number(raw));
    }
  });

  if (error) return { ok: false, error };
  const matrix = [];
  for (let i = 0; i < n; i++) matrix.push(flat.slice(i * n, (i + 1) * n));
  return { ok: true, matrix };
}

/** Read + validate the key, storing it on state.key. */
function loadKey() {
  const read = readKey();
  if (!read.ok) {
    state.key = { ok: false, malformed: true, error: read.error };
    return state.key;
  }
  const a = analyzeKey(read.matrix);
  if (!a.ok) {
    state.key = Object.assign(a, {
      malformed: false,
      error: `gcd(det(K), 26) = ${a.gcd}, so no modular inverse exists.`
    });
  } else {
    state.key = a;
  }
  return state.key;
}

/* ============================================================
   6. TEXT PROCESSING (case, punctuation, padding, blocks)
   ============================================================ */
function processMessage(raw, kind) {
  const isPlain = kind === 'plain';
  const out = { ok: false, error: null, title: '', notices: [], processed: '', removedCount: 0 };

  if (!raw || !raw.trim()) {
    out.title = isPlain ? 'Plaintext Required' : 'Ciphertext Required';
    out.error = isPlain
      ? 'Please enter a plaintext message before encrypting.'
      : 'Please enter a ciphertext message before decrypting.';
    return out;
  }

  const upper = raw.toUpperCase();
  if (/[a-z]/.test(raw)) out.notices.push('Lowercase letters were converted to uppercase.');

  const removedArr = upper.match(/[^A-Z]/g) || [];
  const unique = [...new Set(removedArr)].slice(0, 10);
  out.removedCount = removedArr.length;
  if (removedArr.length) {
    out.notices.push(
      `Removed ${removedArr.length} non-alphabetic character(s): ${unique.map(c => c === ' ' ? 'space' : `"${c}"`).join(', ')}` +
      (unique.length < new Set(removedArr).size ? ', …' : '') +
      '. Spaces and punctuation are not part of the mathematics.'
    );
  }

  const processed = upper.replace(/[^A-Z]/g, '');
  if (!processed) {
    out.title = 'No Letters Found';
    out.error = 'Only alphabetic characters A–Z can be processed. The input contains no letters.';
    return out;
  }
  out.ok = true;
  out.processed = processed;
  return out;
}

function padTo(text, n) {
  let padded = text;
  while (padded.length % n !== 0) padded += 'X';
  return padded;
}

function toBlocks(text, n) {
  const blocks = [];
  for (let i = 0; i < text.length; i += n) blocks.push(text.slice(i, i + n));
  return blocks;
}

/* ============================================================
   7. LIVE PREVIEWS (plaintext + ciphertext panels)
   ============================================================ */
function renderPlainPreview() {
  const n = state.size;
  const t = processMessage(plaintextEl.value, 'plain');
  $('blockN').textContent = n;

  if (!t.ok) {
    $('origPlain').textContent = '—';
    $('procPlain').textContent = '—';
    $('padPlain').textContent = '—';
    $('plainBlocks').textContent = '—';
    state.plainPreview = null;
    if (plaintextEl.value.trim()) setAlert($('plainAlert'), 'error', t.title, t.error);
    else clearAlert($('plainAlert'));
    return t;
  }

  const padded = padTo(t.processed, n);
  const blocks = toBlocks(padded, n);
  state.plainPreview = { ...t, padded, blocks };

  $('origPlain').textContent = plaintextEl.value.trim();
  $('procPlain').textContent = t.processed;
  $('padPlain').textContent = padded;
  $('plainBlocks').textContent = blocks.join(' | ');

  // live notices (errors are written by the encrypt routine afterwards)
  if (padded !== t.processed) {
    t.notices.push(`Plaintext required padding: ${padded.length - t.processed.length} "X" added → length ${padded.length} is divisible by ${n}.`);
    setAlert($('plainAlert'), 'warn', 'Padding Applied', t.notices.join(' '));
  } else if (t.notices.length) {
    setAlert($('plainAlert'), 'info', 'Text Normalisation', t.notices.join(' '));
  } else {
    clearAlert($('plainAlert'));
  }
  plaintextEl.classList.remove('bad');
  return t;
}

function renderCipherPreview() {
  const t = processMessage(ciphertextEl.value, 'cipher');
  if (!t.ok) {
    state.cipherClean = '';
    if (ciphertextEl.value.trim()) setAlert($('cipherAlert'), 'error', t.title, t.error);
    else clearAlert($('cipherAlert'));
    ciphertextEl.classList.toggle('bad', Boolean(ciphertextEl.value.trim()));
    return t;
  }
  state.cipherClean = t.processed;
  ciphertextEl.classList.remove('bad');

  const n = state.size;
  if (t.processed.length % n !== 0) {
    setAlert($('cipherAlert'), 'error', 'Invalid Ciphertext Length',
      `The ciphertext has ${t.processed.length} letters, which is not a multiple of the matrix size ${n}. ` +
      `Add or remove letters so the length is divisible by ${n}.`);
  } else if (t.notices.length) {
    setAlert($('cipherAlert'), 'info', 'Text Normalisation', t.notices.join(' '));
  } else {
    clearAlert($('cipherAlert'));
  }
  return t;
}

/* ============================================================
   8. KEY PANEL + STATS RENDERING
   ============================================================ */
function renderKeyPanel() {
  const k = state.key;
  const valid = k && k.ok;

  $('detValue').textContent = k && k.det !== undefined ? k.det : '—';
  $('detModValue').textContent = k && k.detMod !== undefined ? k.detMod : '—';
  $('gcdValue').textContent = k && k.gcd !== undefined ? k.gcd : '—';

  const status = $('keyStatusText');
  status.textContent = valid ? 'Valid' : 'Invalid';
  status.className = valid ? 'ok' : 'bad';

  const box = $('inverseBox');
  const detLine = k && k.det !== undefined ? k.det : '—';
  const detModLine = k && k.detMod !== undefined ? k.detMod : '—';
  const detInvLine = valid ? k.detInverse : '—';
  const invMat = valid
    ? matrixHTML(k.inv, 'violet')
    : '<span class="mview violet mini"><span class="mgrid"><span class="mval muted">—</span></span></span>';

  box.classList.toggle('disabled', !valid);
  box.innerHTML = `
    <div class="inv-line"><span>Determinant:</span><b class="mono">${detLine}</b></div>
    <div class="inv-line"><span>det(K) mod 26:</span><b class="mono">${detModLine}</b></div>
    <div class="inv-line"><span>Multiplicative inverse of determinant:</span><b class="mono">${detInvLine}</b></div>
    <div class="inv-matrix">
      <span class="inv-label">Inverse Key Matrix:</span>
      ${invMat}
    </div>`;

  // key panel alert
  if (k && k.malformed) {
    setAlert($('keyAlert'), 'error', 'Invalid Key Matrix', k.error);
  } else if (k && !k.ok) {
    setAlert($('keyAlert'), 'error', 'Invalid Key Matrix',
      'The determinant of the key matrix must be relatively prime to 26. ' + k.error);
  } else if (k && k.ok) {
    setAlert($('keyAlert'), 'info', 'Valid Key Matrix',
      `gcd(${k.det}, 26) = 1, so K is invertible modulo 26. ` +
      `Inverse computed as K⁻¹ = ${k.detInverse} × adj(K) mod 26.`);
  } else {
    clearAlert($('keyAlert'));
  }

  renderDecInverse();
}

function renderDecInverse() {
  const k = state.key;
  const valid = k && k.ok;
  const el = $('decInverse');
  if (!valid) {
    el.innerHTML = `
      <h4>Modular Inverse of the Key Matrix</h4>
      <p>Enter a valid ${state.size}×${state.size} key matrix above — the determinant must be relatively prime to 26 before K⁻¹ can be computed.</p>`;
    return;
  }
  el.innerHTML = `
    <h4>Modular Inverse of the Key Matrix</h4>
    <div class="inv-grid">
      <div>Determinant<b>${k.det}</b></div>
      <div>det(K) mod 26<b>${k.detMod}</b></div>
      <div>Multiplicative inverse of determinant<b>${k.detInverse}</b></div>
    </div>
    <span class="inv-label">Inverse Key Matrix:</span>
    ${matrixHTML(k.inv, 'violet')}`;
}

function renderStats() {
  const k = state.key;
  const n = state.size;

  $('statSize').textContent = `${n}×${n}`;
  $('statDet').textContent = (k && k.det !== undefined) ? k.det : '—';

  const pill = $('statKey');
  if (k && k.ok) { pill.textContent = 'Valid'; pill.className = 'pill valid'; }
  else if (k) { pill.textContent = 'Invalid'; pill.className = 'pill invalid'; }
  else { pill.textContent = '—'; pill.className = 'pill neutral'; }

  const p = state.plainPreview;
  $('statPlain').textContent = p
    ? (p.padded.length !== p.processed.length ? `${p.processed.length} → ${p.padded.length}` : `${p.processed.length}`)
    : '—';

  const cipherLen = state.cipherClean ? state.cipherClean.length
                  : (state.lastCipher ? state.lastCipher.length : null);
  $('statCipher').textContent = cipherLen === null ? '—' : cipherLen;
  $('statOp').textContent = state.operation;
}

/* ============================================================
   9. FLOW VISUALIZATION
   ============================================================ */
function renderFlow(el, labels) {
  el.innerHTML = labels.map((label, i) => {
    const cls = i === 0 ? 'start'
      : i === labels.length - 1 ? 'end'
      : /Matrix|Determinant/.test(label) ? 'key' : '';
    const arrow = i < labels.length - 1 ? '<span class="flow-arrow">↓</span>' : '';
    return `<span class="flow-node ${cls}">${esc(label)}</span>${arrow}`;
  }).join('');
}

/* ============================================================
   10. ENCRYPTION
   ============================================================ */
function runEncryption(silent) {
  const k = state.key;
  const alertEl = $('plainAlert');

  // ---- key must be valid first
  if (!k || !k.ok) {
    state.lastCipher = '';
    $('cipherOut').textContent = '—';
    $('cipherNote').textContent = 'Encryption blocked until a valid key matrix is entered';
    $('encSteps').innerHTML = `<p class="empty">Encryption is disabled — enter a ${state.size}×${state.size} key matrix whose determinant is relatively prime to 26.</p>`;
    if (!silent || k) {
      setAlert(alertEl, 'error', 'Invalid Key Matrix',
        k && k.malformed ? k.error
          : 'The determinant of the key matrix must be relatively prime to 26. Encryption is not possible.');
    }
    return false;
  }

  // ---- plaintext
  const t = renderPlainPreview();
  if (!t.ok) {
    state.lastCipher = '';
    $('cipherOut').textContent = '—';
    $('cipherNote').textContent = 'Enter a plaintext message to encrypt';
    $('encSteps').innerHTML = '<p class="empty">No plaintext available — type a message above.</p>';
    setAlert(alertEl, 'error', t.title, t.error);
    return false;
  }

  const n = state.size;
  const padded = state.plainPreview.padded;
  const blocks = state.plainPreview.blocks;
  state.lastEncPadded = padded;

  // ---- encrypt every block: C = K × P mod 26
  let cipher = '';
  const stepHTML = blocks.map((block, idx) => {
    const p = [...block].map(ch => ALPHABET.indexOf(ch));
    const raw = k.K.map(row => row.reduce((s, coeff, j) => s + coeff * p[j], 0));
    const cvec = raw.map(v => mod(v));
    const letters = cvec.map(v => ALPHABET[v]).join('');
    cipher += letters;

    const arith = k.K.map((row, i) => {
      const terms = row.map((coeff, j) => `${coeff}×${p[j]}`).join(' + ');
      return `<li>Row ${i + 1}: ${terms} = <b>${raw[i]}</b> → ${raw[i]} mod 26 = <b>${cvec[i]}</b> → <span class="res">${ALPHABET[cvec[i]]}</span></li>`;
    }).join('');

    return `
      <div class="step-card" style="animation-delay:${Math.min(idx * 0.05, 0.4)}s">
        <div class="step-head">
          <span class="step-num">Block ${idx + 1} / ${blocks.length}</span>
          <span class="step-block">${esc(block)}</span>
        </div>
        <div class="equation">
          ${matrixHTML(k.K, 'hl')}
          <span class="op">×</span>
          ${matrixHTML(vectorOf(p), 'violet')}
          <span class="op">=</span>
          ${matrixHTML(vectorOf(raw), 'amber')}
          <span class="op mod">mod 26</span>
          <span class="op">=</span>
          ${matrixHTML(vectorOf(cvec), 'green')}
          <span class="op">→</span>
          <span class="vec-letters">${letters}</span>
        </div>
        <ul class="arith">${arith}</ul>
        <div class="step-foot">
          <span>${block.split('').map((ch, i) => `${ch}=${p[i]}`).join(' · ')}</span>
          <span>Block ciphertext <b>${letters}</b></span>
        </div>
      </div>`;
  }).join('');

  state.lastCipher = cipher;
  state.operation = 'Encryption';

  $('cipherOut').textContent = cipher;
  $('cipherNote').textContent =
    `${cipher.length} letters · ${blocks.length} block(s) · key ${n}×${n} · det(K) = ${k.det}`;
  $('encSteps').innerHTML =
    `<p class="steps-summary">${blocks.length} block(s) · C = K × P mod 26 · every value computed live</p>` + stepHTML;

  const box = document.querySelector('.enc-result');
  if (!silent) { box.classList.remove('flash'); void box.offsetWidth; box.classList.add('flash'); }
  renderPlainPreview();   // keep lower-case / punctuation / padding notices visible
  renderStats();
  return true;
}

/* ============================================================
   11. DECRYPTION
   ============================================================ */
function runDecryption(silent) {
  const k = state.key;
  const alertEl = $('cipherAlert');

  // ---- key must be valid first
  if (!k || !k.ok) {
    $('plainOut').textContent = '—';
    $('plainNote').textContent = 'Decryption blocked until a valid key matrix is entered';
    $('decSteps').innerHTML = `<p class="empty">Decryption is disabled — K⁻¹ (mod 26) does not exist for this key matrix.</p>`;
    setAlert(alertEl, 'error', 'Invalid Key Matrix',
      k && k.malformed ? k.error
        : 'The determinant of the key matrix must be relatively prime to 26, so no inverse key matrix exists.');
    return false;
  }

  // ---- ciphertext
  const t = renderCipherPreview();
  if (!t.ok) {
    $('plainOut').textContent = '—';
    $('plainNote').textContent = 'Enter a ciphertext message to decrypt';
    $('decSteps').innerHTML = '<p class="empty">No ciphertext available — type a message above.</p>';
    setAlert(alertEl, 'error', t.title, t.error);
    return false;
  }

  const n = state.size;
  const cleaned = t.processed;
  if (cleaned.length % n !== 0) {
    $('plainOut').textContent = '—';
    $('plainNote').textContent = 'Fix the ciphertext length, then decrypt again';
    $('decSteps').innerHTML = '<p class="empty">Waiting for a ciphertext whose length is a multiple of the matrix size.</p>';
    setAlert(alertEl, 'error', 'Invalid Ciphertext Length',
      `${cleaned.length} letters is not divisible by the matrix size ${n}. ` +
      `The ciphertext must contain a multiple of ${n} letters (e.g. ${Math.ceil(cleaned.length / n) * n}).`);
    return false;
  }

  const blocks = toBlocks(cleaned, n);
  let plain = '';

  const stepHTML = blocks.map((block, idx) => {
    const c = [...block].map(ch => ALPHABET.indexOf(ch));
    const raw = k.inv.map(row => row.reduce((s, coeff, j) => s + coeff * c[j], 0));
    const pvec = raw.map(v => mod(v));
    const letters = pvec.map(v => ALPHABET[v]).join('');
    plain += letters;

    const arith = k.inv.map((row, i) => {
      const terms = row.map((coeff, j) => `${coeff}×${c[j]}`).join(' + ');
      return `<li>Row ${i + 1}: ${terms} = <b>${raw[i]}</b> → ${raw[i]} mod 26 = <b>${pvec[i]}</b> → <span class="res">${ALPHABET[pvec[i]]}</span></li>`;
    }).join('');

    return `
      <div class="step-card" style="animation-delay:${Math.min(idx * 0.05, 0.4)}s">
        <div class="step-head">
          <span class="step-num">Block ${idx + 1} / ${blocks.length}</span>
          <span class="step-block">${esc(block)}</span>
        </div>
        <div class="equation">
          ${matrixHTML(k.inv, 'violet')}
          <span class="op">×</span>
          ${matrixHTML(vectorOf(c), 'hl')}
          <span class="op">=</span>
          ${matrixHTML(vectorOf(raw), 'amber')}
          <span class="op mod">mod 26</span>
          <span class="op">=</span>
          ${matrixHTML(vectorOf(pvec), 'green')}
          <span class="op">→</span>
          <span class="vec-letters">${letters}</span>
        </div>
        <ul class="arith">${arith}</ul>
        <div class="step-foot">
          <span>${block.split('').map((ch, i) => `${ch}=${c[i]}`).join(' · ')}</span>
          <span>Recovered block <b>${letters}</b></span>
        </div>
      </div>`;
  }).join('');

  state.operation = 'Decryption';

  const matched = state.lastEncPadded && plain === state.lastEncPadded;
  $('plainOut').textContent = plain;
  $('plainNote').textContent =
    `${plain.length} letters recovered from ${blocks.length} block(s)` +
    (matched ? ' · ✓ matches the original plaintext' : '');

  $('decSteps').innerHTML =
    `<p class="steps-summary">${blocks.length} block(s) · P = K⁻¹ × C mod 26 · K⁻¹ computed live from adj(K) and det(K)⁻¹</p>` + stepHTML;

  const box = document.querySelector('.dec-result');
  if (!silent) { box.classList.remove('flash'); void box.offsetWidth; box.classList.add('flash'); }
  renderCipherPreview();  // keep lower-case / punctuation notices visible
  renderStats();
  return true;
}

/* ============================================================
   12. REFRESH / LIVE UPDATES
   ============================================================ */
function refresh() {
  loadKey();
  renderKeyPanel();
  renderPlainPreview();
  renderCipherPreview();
  renderStats();
  if (state.ranEnc) runEncryption(true);
  if (state.ranDec) runDecryption(true);
}

function clearResults() {
  state.lastCipher = '';
  state.lastEncPadded = '';
  state.ranEnc = false;
  state.ranDec = false;
  $('cipherOut').textContent = '—';
  $('cipherNote').textContent = 'Run the encryption to generate the ciphertext';
  $('plainOut').textContent = '—';
  $('plainNote').textContent = 'Run the decryption to recover the plaintext';
  $('encSteps').innerHTML = '<p class="empty">No results yet — enter a valid key and message, then press Encrypt.</p>';
  $('decSteps').innerHTML = '<p class="empty">No results yet — enter a valid key and ciphertext, then press Decrypt.</p>';
}

/* ============================================================
   13. EXAMPLES + RESET
   ============================================================ */
function loadExample(size) {
  const ex = EXAMPLES[size];
  state.size = size;
  sizeSelect.value = String(size);
  buildMatrix(ex.key);
  plaintextEl.value = ex.plaintext;
  ciphertextEl.value = '';
  clearResults();
  refresh();
  runEncryption(false);
  state.ranEnc = true;
  $('encPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function resetAll() {
  state.size = DEFAULTS.size;
  sizeSelect.value = String(DEFAULTS.size);
  buildMatrix(DEFAULTS.key);
  plaintextEl.value = DEFAULTS.plaintext;
  ciphertextEl.value = DEFAULTS.ciphertext;
  state.operation = '—';
  clearResults();
  ['plainAlert', 'cipherAlert', 'keyAlert'].forEach(id => clearAlert($(id)));
  refresh();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ============================================================
   14. EVENT WIRING + INIT
   ============================================================ */
sizeSelect.addEventListener('change', () => {
  state.size = Number(sizeSelect.value);
  buildMatrix(EXAMPLES[state.size].key);     // fresh, valid key for the new size
  clearResults();                            // no page reload, results regenerate on demand
  refresh();
});

plaintextEl.addEventListener('input', () => {
  renderPlainPreview();
  renderStats();
  if (state.ranEnc) runEncryption(true);
});

ciphertextEl.addEventListener('input', () => {
  renderCipherPreview();
  renderStats();
  if (state.ranDec) runDecryption(true);
});

ciphertextEl.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); $('decryptBtn').click(); }
});

$('encryptBtn').addEventListener('click', () => {
  renderPlainPreview();
  const ok = runEncryption(false);
  state.ranEnc = ok;
  renderStats();
});

$('decryptBtn').addEventListener('click', () => {
  renderCipherPreview();
  const ok = runDecryption(false);
  state.ranDec = ok;
  renderStats();
});

document.querySelectorAll('[data-example]').forEach(btn => {
  btn.addEventListener('click', () => loadExample(Number(btn.dataset.example)));
});

$('resetBtn').addEventListener('click', resetAll);

/* ---- initial render ---- */
renderFlow($('encFlow'), ENC_FLOW);
renderFlow($('decFlow'), DEC_FLOW);
buildMatrix(DEFAULTS.key);
clearResults();
refresh();
