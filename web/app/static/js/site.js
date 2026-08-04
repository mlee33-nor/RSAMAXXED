/* ============================================================================
   RSAMAXXED — site interactions
   ----------------------------------------------------------------------------
   No dependencies, no CDN (the CSP forbids external origins anyway).
   Everything degrades: if a node is missing, that module quietly no-ops; if
   the visitor asks for reduced motion, animations render their final frame.
   ========================================================================= */
'use strict';

const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
const FINE_POINTER = matchMedia('(pointer:fine)').matches;

/* One breakpoint, shared by the fan-out's JS and its CSS. Below it the broker
   chips stack into a list and the wires run down a left-hand spine. */
const STACKED = matchMedia('(max-width:860px)');

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const money = n =>
  '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

/* ============================================================================
   THE SCENARIO — one source of truth for every number on this site.
   ----------------------------------------------------------------------------
   A sub-$1 company facing delisting reverse-splits to lift its bid over the
   exchange minimum. Buy one share at $0.25; a 1-for-20 leaves you 0.05 of a
   share; a broker that rounds up hands back one WHOLE share, now marked near
   $5.00. You paid a quarter for it.

       per account = entry x (ratio - 1)   =  0.25 x 19  =  $4.75
       total       = accounts x per account

   Change these three numbers and the hero, the fan-out and the explainer all
   move together. Nothing about the payout is hardcoded anywhere else.
   ========================================================================= */
const RSA = Object.freeze({ entry: 0.25, ratio: 20, accounts: 10 });

const perAccount = (entry = RSA.entry, ratio = RSA.ratio) => entry * (ratio - 1);
const postPrice = (entry = RSA.entry, ratio = RSA.ratio) => entry * ratio;

/* ------------------------------------------------------------------ nav ---
   A sentinel + IntersectionObserver rather than a scroll listener: this fires
   twice in the page's life instead of on every frame of every scroll. */
function initNav() {
  const nav = $('.nav');
  if (!nav) return;
  const sentinel = document.createElement('div');
  sentinel.style.cssText = 'position:absolute;top:0;height:1px;width:1px';
  document.body.prepend(sentinel);
  new IntersectionObserver(([e]) => nav.classList.toggle('stuck', !e.isIntersecting),
    { threshold: 0 }).observe(sentinel);
}

/* --------------------------------------------- pointer: spotlight + parallax
   One rAF-coalesced handler drives three effects. Writing CSS custom properties
   and letting the compositor do the rest beats animating anything in JS. */
function initPointerFx() {
  if (REDUCED || !FINE_POINTER) return;
  document.body.classList.add('pointer-fine');

  const spot = $('.spotlight');
  const gridSpot = $('.grid-spot');
  const auroraWrap = $('.aurora-wrap');

  let x = innerWidth / 2, y = innerHeight / 2, queued = false;

  const flush = () => {
    queued = false;
    const px = x + 'px', py = y + 'px';
    spot?.style.setProperty('--mx', px);
    spot?.style.setProperty('--my', py);
    gridSpot?.style.setProperty('--mx', px);
    gridSpot?.style.setProperty('--my', py);

    if (auroraWrap) {
      // Deliberately tiny: the aurora leans toward the cursor, it doesn't chase it.
      const dx = (x / innerWidth - .5) * 44;
      const dy = (y / innerHeight - .5) * 26;
      auroraWrap.style.setProperty('--px', dx.toFixed(1) + 'px');
      auroraWrap.style.setProperty('--py', dy.toFixed(1) + 'px');
    }
  };

  addEventListener('pointermove', e => {
    x = e.clientX; y = e.clientY;
    if (!queued) { queued = true; requestAnimationFrame(flush); }
  }, { passive: true });

  // Per-card glow. The listener lives on the card, so it only runs while hovered.
  $$('.card.interactive').forEach(card => {
    card.addEventListener('pointermove', e => {
      const r = card.getBoundingClientRect();
      card.style.setProperty('--cx', (e.clientX - r.left) + 'px');
      card.style.setProperty('--cy', (e.clientY - r.top) + 'px');
    }, { passive: true });
  });

  flush();
}

/* ------------------------------------------------------- reveal fallback ---
   Browsers with animation-timeline: view() handle reveals in CSS, on the
   compositor. Firefox (still flagged in 2026) lands here instead. */
function initReveal() {
  if (CSS.supports('animation-timeline', 'view()')) return;
  const els = $$('.reveal');
  if (REDUCED) { els.forEach(el => el.classList.add('in-view')); return; }
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add('in-view'); io.unobserve(e.target); }
    });
  }, { rootMargin: '0px 0px -12% 0px' });
  els.forEach(el => io.observe(el));
}

/* ------------------------------------------------------------------ scenes
   The explainer's diagrams animate once, when you scroll to them. This needs
   its own observer rather than piggybacking on .reveal, because .reveal short-
   circuits to a pure-CSS scroll timeline in Chrome and never sets a class. */
function initScenes() {
  const els = $$('.scene');
  if (!els.length) return;
  if (REDUCED) { els.forEach(el => el.classList.add('lit')); return; }
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add('lit'); io.unobserve(e.target); }
    });
  }, { threshold: .35 });
  els.forEach(el => io.observe(el));
}

/* ----------------------------------------------------------- odometers --- */
/* One animation per element, ever. The fan-out retargets this odometer each
   time a broker fills — roughly every 70ms, against a 420ms ease — so without
   cancellation half a dozen rAF loops end up writing to the same node and the
   total visibly counts backwards. A retarget resumes from whatever is on
   screen right now, which is also what makes the ease look continuous. */
const _ticks = new WeakMap();

function cancelTick(el) {
  const rec = _ticks.get(el);
  if (rec) { cancelAnimationFrame(rec.raf); _ticks.delete(el); }
}

function tickTo(el, from, to, dur = 900, fmt = v => v.toFixed(2)) {
  const prev = _ticks.get(el);
  if (prev) { cancelAnimationFrame(prev.raf); from = prev.value; }
  if (REDUCED) { _ticks.delete(el); el.textContent = fmt(to); return; }

  const t0 = performance.now();
  const step = now => {
    const p = clamp((now - t0) / dur, 0, 1);
    const eased = 1 - Math.pow(1 - p, 4);
    const v = from + (to - from) * eased;
    el.textContent = fmt(v);
    if (p < 1) {
      const rec = _ticks.get(el);
      if (rec) { rec.value = v; rec.raf = requestAnimationFrame(step); }
    } else {
      _ticks.delete(el);
    }
  };
  _ticks.set(el, { raf: requestAnimationFrame(step), value: from });
}

function initCounters() {
  const els = $$('[data-count-to]');
  if (!els.length) return;
  const run = el => {
    const to = parseFloat(el.dataset.countTo);
    const dp = parseInt(el.dataset.countDp ?? '0', 10);
    const pre = el.dataset.countPre ?? '';
    const post = el.dataset.countPost ?? '';
    const fmt = v => pre + v.toLocaleString('en-US',
      { minimumFractionDigits: dp, maximumFractionDigits: dp }) + post;
    tickTo(el, 0, to, 1100, fmt);
  };
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { run(e.target); io.unobserve(e.target); } });
  }, { threshold: .5 });
  els.forEach(el => io.observe(el));
}

/* ======================================================================== */
/* THE ROUND-UP ENGINE                                                       */
/* ------------------------------------------------------------------------ */
/* Not a mock-up. All three sliders drive the real arithmetic, and the        */
/* headline figure is always the answer to them.                             */
/*                                                                          */
/* Pacing note: the caption under the canvas names the phase you are looking */
/* at. It used to change four times in four and a half seconds, which read   */
/* as a flicker rather than a sentence. Each beat now outlasts the time it    */
/* takes to read it, and the caption cross-fades instead of snapping.        */
/* ======================================================================== */
function initRoundupEngine() {
  const cv = $('#roundup');
  if (!cv) return;

  const ctx = cv.getContext('2d');
  const ratioEl = $('#r-ratio'), acctEl = $('#r-accts'), priceEl = $('#r-price');
  const ratioOut = $('#r-ratio-out'), acctOut = $('#r-accts-out'), priceOut = $('#r-price-out');
  const profitOut = $('#r-profit'), subOut = $('#r-sub'), phaseOut = $('#r-phase');
  const postOut = $('#r-post');

  let ratio = RSA.ratio, accounts = RSA.accounts, entry = RSA.entry;
  let W = 0, H = 0, dpr = 1;
  let raf = 0, visible = true, lastPhase = '';

  // Each beat is held long enough to actually read its caption.
  const T = { hold: 2400, shrink: 1700, snap: 900, settle: 4000 };
  const TOTAL = T.hold + T.shrink + T.snap + T.settle;
  let t0 = performance.now();

  const per = () => perAccount(entry, ratio);
  const profit = () => accounts * per();

  function resize() {
    dpr = Math.min(devicePixelRatio || 1, 2);   // 3x on phones is wasted fill rate
    const r = cv.getBoundingClientRect();
    W = r.width; H = r.height;
    cv.width = Math.round(W * dpr);
    cv.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  const easeOut = p => 1 - Math.pow(1 - p, 3);
  const easeBack = p => { const c = 1.9; return 1 + (c + 1) * (p - 1) ** 3 + c * (p - 1) ** 2; };

  function phaseAt(e) {
    if (e < T.hold) return { phase: 'hold', k: e / T.hold };
    e -= T.hold;
    if (e < T.shrink) return { phase: 'shrink', k: e / T.shrink };
    e -= T.shrink;
    if (e < T.snap) return { phase: 'snap', k: e / T.snap };
    e -= T.snap;
    return { phase: 'settle', k: e / T.settle };
  }

  /* Solve for the column count that yields the squarest cell. n runs to 55, so
     a fixed 5x2 grid would spill; this keeps 1 and 55 both looking deliberate. */
  function layout() {
    const padX = 30, padY = 34;
    const availW = W - padX * 2, availH = H - padY * 2;
    let best = { cols: 1, rows: accounts, cell: 0, cw: availW, ch: availH };

    for (let cols = 1; cols <= accounts; cols++) {
      const rows = Math.ceil(accounts / cols);
      const cw = availW / cols, ch = availH / rows;
      const cell = Math.min(cw, ch);
      if (cell > best.cell) best = { cols, rows, cell, cw, ch };
    }

    const { cols, rows, cw, ch } = best;
    const pts = [];
    for (let i = 0; i < accounts; i++) {
      const c = i % cols, r = Math.floor(i / cols);
      // Centre a short final row instead of left-aligning it.
      const inRow = Math.min(cols, accounts - r * cols);
      const offset = (cols - inRow) * cw / 2;
      pts.push({ x: padX + offset + cw * (c + .5), y: padY + ch * (r + .5) });
    }
    return { pts, cell: best.cell };
  }

  function caption(phase) {
    const frac = (1 / ratio).toFixed(ratio > 50 ? 3 : 2);
    switch (phase) {
      case 'hold':
        return `${accounts} account${accounts > 1 ? 's' : ''} · 1 share each @ ${money(entry)}`;
      case 'shrink':
        return `1-for-${ratio} reverse split → ${frac} of a share`;
      case 'snap':
        return 'BROKER ROUNDS THE FRACTION UP → 1 whole share';
      default:
        return `${accounts} whole share${accounts > 1 ? 's' : ''} near ${money(postPrice(entry, ratio))} — sell, keep ${money(per())} each`;
    }
  }

  function setCaption(phase) {
    if (!phaseOut) return;
    phaseOut.textContent = caption(phase);
    phaseOut.classList.remove('swap');
    void phaseOut.offsetWidth;                  // restart the fade
    phaseOut.classList.add('swap');
  }

  function draw(now) {
    const elapsed = REDUCED ? TOTAL - 1 : (now - t0) % TOTAL;
    const { phase, k } = phaseAt(elapsed);
    const { pts, cell } = layout();

    const rFull = clamp(cell * 0.30, 3, 34);
    const rFrac = rFull / Math.sqrt(ratio);      // area scales as 1/R — honest
    // At 55 accounts a per-dot share label repeats 55 times and reads as noise;
    // the caption underneath already says what every dot is doing.
    const showLabels = cell >= 58;
    const showMoney = cell >= 44;

    if (phase !== lastPhase) {
      setCaption(phase);
      if (phase === 'snap') {
        profitOut?.classList.remove('pop');
        void profitOut?.offsetWidth;             // restart the CSS animation
        profitOut?.classList.add('pop');
      }
    }
    lastPhase = phase;

    ctx.clearRect(0, 0, W, H);

    let rNow = rFull, ring = 0, rounded = false;
    if (phase === 'shrink') rNow = rFull + (rFrac - rFull) * easeOut(k);
    else if (phase === 'snap') { rNow = rFrac + (rFull - rFrac) * easeBack(k); ring = 1 - k; rounded = true; }
    else if (phase === 'settle') { rNow = rFull; rounded = true; }

    ctx.textAlign = 'center';

    for (const p of pts) {
      // ghost of the whole share you started with
      ctx.beginPath();
      ctx.arc(p.x, p.y, rFull, 0, Math.PI * 2);
      ctx.strokeStyle = '#2a3145';
      ctx.setLineDash([3, 4]);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);

      if (ring > 0) {                            // round-up shockwave
        ctx.beginPath();
        ctx.arc(p.x, p.y, rFull + 14 * (1 - ring), 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(52,211,158,${ring * .85})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, Math.max(rNow, 1.2), 0, Math.PI * 2);
      const g = ctx.createLinearGradient(p.x - rNow, p.y - rNow, p.x + rNow, p.y + rNow);
      if (rounded) { g.addColorStop(0, '#4ade9f'); g.addColorStop(1, '#22b98a'); }
      else { g.addColorStop(0, '#9d9aff'); g.addColorStop(1, '#6360e6'); }
      ctx.fillStyle = g;
      ctx.fill();

      if (showLabels) {
        ctx.font = '500 10px ui-monospace,"Cascadia Code",monospace';
        ctx.fillStyle = '#949aab';
        const sh = phase === 'shrink' ? (1 / ratio).toFixed(2) : '1.00';
        ctx.fillText(sh + ' sh', p.x, p.y + rFull + 16);
      }

      // The money, lifting out of each account as it rounds up.
      if (showMoney && (phase === 'snap' || phase === 'settle')) {
        const mp = phase === 'snap' ? k * .45 : clamp(.45 + k * 1.3, 0, 1);
        const rise = 10 + mp * 16;
        ctx.globalAlpha = mp < .12 ? mp / .12 : clamp(1 - (mp - .55) / .45, 0, 1);
        ctx.font = '600 11px ui-monospace,"Cascadia Code",monospace';
        ctx.fillStyle = '#34d39e';
        ctx.fillText('+' + money(per()), p.x, p.y - rFull - rise);
        ctx.globalAlpha = 1;
      }
    }

    if (!REDUCED && visible) raf = requestAnimationFrame(draw);
  }

  function restart() {
    t0 = performance.now();
    lastPhase = '';
    if (!raf && visible) raf = requestAnimationFrame(draw);
  }

  function syncLabels() {
    if (ratioOut) ratioOut.textContent = `1-for-${ratio}`;
    if (acctOut) acctOut.textContent = accounts;
    if (priceOut) priceOut.textContent = money(entry);
    if (postOut) postOut.textContent = money(postPrice(entry, ratio));
    // The headline is always the answer, live with the sliders.
    if (profitOut) profitOut.textContent = '+' + money(profit());
    if (subOut) {
      subOut.textContent =
        `${money(per())} per account × ${accounts}. Each ${money(entry)} share comes back ` +
        `as one whole share near ${money(postPrice(entry, ratio))}.`;
    }
  }

  ratioEl?.addEventListener('input', () => { ratio = +ratioEl.value; syncLabels(); restart(); });
  acctEl?.addEventListener('input', () => { accounts = +acctEl.value; syncLabels(); restart(); });
  // Cents on the slider, dollars in the model — keeps the step exact.
  priceEl?.addEventListener('input', () => { entry = +priceEl.value / 100; syncLabels(); restart(); });

  // Don't burn a rAF loop on a canvas nobody is looking at.
  new IntersectionObserver(([e]) => {
    visible = e.isIntersecting;
    if (visible && !raf) raf = requestAnimationFrame(draw);
    else if (!visible && raf) { cancelAnimationFrame(raf); raf = 0; }
  }, { threshold: .05 }).observe(cv);

  new ResizeObserver(() => { resize(); if (REDUCED) draw(performance.now()); }).observe(cv);

  resize(); syncLabels();
  if (REDUCED) { setCaption('settle'); draw(performance.now()); } else restart();
}

/* ======================================================================== */
/* MIRROR FAN-OUT — one order, ten brokers, money landing one by one         */
/* ------------------------------------------------------------------------ */
/* The wires used to be display:none under 980px, so the whole point of the  */
/* section — a single order splitting ten ways — simply vanished on a phone   */
/* and the chips lit up for no visible reason. Now the SVG overlays the       */
/* stage at every width and the geometry adapts: chips in a row get wires     */
/* dropped onto their top edge; chips in a stack get a ribbon of ten strands  */
/* running down a left-hand gutter, each peeling off into its own row.        */
/* ======================================================================== */
function initFanout() {
  const svg = $('#fanout');
  const btn = $('#fire');
  const sumEl = $('#fan-sum');
  const wrap = $('.fan-wrap');
  if (!svg || !btn || !wrap) return;

  const NS = 'http://www.w3.org/2000/svg';
  const nodes = $$('.bnode');
  const PER = perAccount();            // $4.75 — the same quarter-share trade
  let running = false;

  nodes.forEach(n => {
    const m = document.createElement('span');
    m.className = 'money';
    m.textContent = '+' + money(PER);
    n.appendChild(m);
  });

  // Hard-set, cancelling any odometer still in flight from the previous run.
  const setSum = v => { if (sumEl) { cancelTick(sumEl); sumEl.textContent = '+' + money(v); } };

  /** One path per broker, or [] if the stage has not been laid out yet (a
      zero-size rect would aim every packet at 0,0). */
  function buildWires() {
    svg.querySelectorAll('.wire,.packet').forEach(el => el.remove());
    const box = svg.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) return [];

    const ox = box.width / 2, oy = 2;
    const stacked = STACKED.matches;
    const last = Math.max(1, nodes.length - 1);

    // Stacked: fan out above the first chip, then run straight down the gutter.
    // Curving all the way from the button to each row would drag the wires
    // across the chip column, and the chips are translucent enough to show it.
    const firstTop = nodes[0].getBoundingClientRect().top - box.top;
    const trunk = Math.max(firstTop - 16, oy + 12);

    return nodes.map((node, i) => {
      const nb = node.getBoundingClientRect();
      let d;

      if (stacked) {
        // Each strand claims its own lane in the gutter, then hooks right into
        // its row's left edge.
        const x = nb.left - box.left;
        const y = nb.top - box.top + nb.height / 2;
        const lane = 8 + i * (26 / last);        // 8 -> 34px, ten parallel strands
        d = `M${ox},${oy} C${ox},${oy + (trunk - oy) * .45} ${lane},${trunk - 12} ${lane},${trunk} `
          + `L${lane},${y} L${x},${y}`;
      } else {
        // Land exactly on the chip's top edge.
        const x = nb.left - box.left + nb.width / 2;
        const y = nb.top - box.top;
        const midY = oy + (y - oy) * .55;
        d = `M${ox},${oy} C${ox},${midY} ${x},${midY} ${x},${y}`;
      }

      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', d);
      path.setAttribute('class', 'wire');
      svg.appendChild(path);
      path.style.setProperty('--len', path.getTotalLength());
      return path;
    });
  }

  function reset() {
    nodes.forEach(n => {
      n.classList.remove('filled');
      const st = n.querySelector('.st');
      if (st) st.textContent = 'idle';
    });
    svg.querySelectorAll('.wire').forEach(w => w.classList.remove('live'));
    svg.querySelectorAll('.packet').forEach(p => p.remove());
    setSum(0);
  }

  function fill(node, ms, sumSoFar) {
    node.classList.add('filled');
    const st = node.querySelector('.st');
    if (st) st.textContent = Math.round(ms) + 'ms';
    if (sumEl) tickTo(sumEl, sumSoFar - PER, sumSoFar, 420, v => '+' + money(v));
  }

  btn.addEventListener('click', () => {
    if (running) return;
    running = true;
    btn.disabled = true;
    btn.classList.add('firing');
    reset();

    // Each fill() advances the odometer to its own running total, so the last
    // one always lands on the full sum. Writing the total here as well would
    // snap the number to $47.50 and then let the in-flight odometer drag it
    // back down for another 420ms.
    if (REDUCED) {
      nodes.forEach((n, i) => fill(n, 0, PER * (i + 1)));
      return done();
    }

    const paths = buildWires();
    const wired = paths.length === nodes.length;

    // Real brokers don't answer in lockstep. Jitter is what makes this read true.
    const trips = nodes.map((node, i) => {
      const start = i * 70;
      const dur = 620 + Math.random() * 760;
      const trip = { start, dur, landed: false, node, path: null, dot: null, len: 0 };
      if (wired) {
        const path = paths[i];
        const dot = document.createElementNS(NS, 'circle');
        dot.setAttribute('r', '3');
        dot.setAttribute('class', 'packet');
        dot.setAttribute('opacity', '0');
        svg.appendChild(dot);
        path.style.setProperty('--d', start + 'ms');
        path.classList.add('live');
        Object.assign(trip, { path, dot, len: path.getTotalLength() });
      }
      return trip;
    });

    const t0 = performance.now();
    let landedCount = 0;

    const step = now => {
      const t = now - t0;
      let alive = false;

      for (const tr of trips) {
        if (tr.landed) continue;
        alive = true;
        const p = (t - tr.start) / tr.dur;
        if (p < 0) continue;
        if (p >= 1) {
          tr.landed = true;
          tr.dot?.remove();
          landedCount++;
          fill(tr.node, tr.dur, PER * landedCount);
          continue;
        }
        if (!tr.path) continue;               // no wires: chips still fill on time
        const pt = tr.path.getPointAtLength(tr.len * (1 - Math.pow(1 - p, 2)));
        tr.dot.setAttribute('cx', pt.x);
        tr.dot.setAttribute('cy', pt.y);
        tr.dot.setAttribute('opacity', String(clamp(p * 5, 0, 1)));
      }

      if (alive) requestAnimationFrame(step);
      else done();
    };
    requestAnimationFrame(step);
  });

  function done() {
    running = false;
    btn.disabled = false;
    btn.classList.remove('firing');
    btn.classList.add('again');
  }

  // A rotation or a breakpoint cross invalidates every path we drew.
  addEventListener('resize', () => {
    if (!running) svg.querySelectorAll('.wire,.packet').forEach(el => el.remove());
  }, { passive: true });

  setSum(0);
}

/* ---------------------------------------------------------------- range fx */
function initRanges() {
  $$('input[type=range]').forEach(el => {
    const paint = () => {
      const pct = (el.value - el.min) / (el.max - el.min) * 100;
      el.style.setProperty('--pct', pct + '%');
    };
    el.addEventListener('input', paint, { passive: true });
    paint();
  });
}

/* ------------------------------------------------------------------ pricing
   Monthly <-> annual. Each price carries both figures as data attributes, so
   the swap is a text write and never a re-layout. */
function initPricing() {
  const toggle = $('#billing');
  if (!toggle) return;
  const apply = () => {
    const annual = toggle.checked;
    document.body.classList.toggle('annual', annual);
    $$('[data-monthly]').forEach(el => {
      el.textContent = annual ? el.dataset.annual : el.dataset.monthly;
    });
  };
  toggle.addEventListener('change', apply);
  apply();
}

/* ------------------------------------------------------------------ explain
   The account multiplier on the explainer page. Same arithmetic as the hero,
   different clothes: drag the count, watch one split's takings scale. */
function initMultiplier() {
  const el = $('#m-accts');
  if (!el) return;
  const out = $('#m-accts-out'), total = $('#m-total'), grid = $('#m-grid');

  const paint = () => {
    const n = +el.value;
    if (out) out.textContent = n;
    if (total) total.textContent = '+' + money(n * perAccount());
    if (grid) {
      // Reuse existing cells; only add or remove the difference.
      while (grid.children.length < n) {
        const cell = document.createElement('i');
        cell.title = '+' + money(perAccount());
        grid.appendChild(cell);
      }
      while (grid.children.length > n) grid.lastChild.remove();
    }
  };
  el.addEventListener('input', paint, { passive: true });
  paint();
}

/* -------------------------------------------------------------------- boot */
function boot() {
  initNav();
  initPointerFx();
  initReveal();
  initScenes();
  initCounters();
  initRanges();
  initRoundupEngine();
  initFanout();
  initPricing();
  initMultiplier();
}

if (document.readyState === 'loading') addEventListener('DOMContentLoaded', boot);
else boot();
