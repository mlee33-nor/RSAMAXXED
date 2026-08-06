/* ============================================================================
   RSAMAXXED — site interactions
   ----------------------------------------------------------------------------
   No dependencies, no CDN (the CSP forbids external origins anyway).
   Everything degrades: if a node is missing, that module quietly no-ops; if
   the visitor asks for reduced motion, animations render their final frame.
   ========================================================================= */
'use strict';

/* Set here rather than in boot(), so it lands the moment this deferred file
   starts executing instead of a frame later. Controls that CANNOT work without
   this file — the "bought" checkboxes on the plays board are the only ones —
   stay hidden until it does. Everything else on the site renders and reads with
   scripts blocked, and must keep doing so. */
document.documentElement.classList.add('js');

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

/* ============================================================================
   THE PLAYS DASHBOARD
   ----------------------------------------------------------------------------
   Money is finished here, in the browser, and never on the server. The
   multiplier is the reader's own per-broker account counts, which live in this
   machine's localStorage and are never transmitted.

   The rule, which is the whole point and is easy to get wrong:

       a play pays YOUR accounts AT THE BROKERS IT ACTUALLY PAID IN

   Not "profit per account x how many accounts you have". The server ships each
   payout with the broker list it was really settled in — taken from the sell
   alert's legs where one exists, and from the tracker's outcome where it
   doesn't — and this multiplies against the accounts you hold at exactly those
   brokers. A split that only sold at Chase pays your Chase accounts. Nothing
   else. Every figure on the page is server-rendered first at one account per
   broker, so the numbers are real and readable before this file runs.
   ========================================================================= */

const ACCT_STORE = 'rsamaxxed.accounts.v2';

function readAccounts() {
  try {
    const raw = JSON.parse(localStorage.getItem(ACCT_STORE) || 'null');
    return (raw && typeof raw === 'object') ? raw : null;
  } catch (e) { return null; }        // blocked storage, private mode, corrupt
}

function writeAccounts(map) {
  try { localStorage.setItem(ACCT_STORE, JSON.stringify(map)); } catch (e) { /* fine */ }
}

/* Compact money for axis ticks, where two decimals are noise. */
const compact = n =>
  Math.abs(n) >= 1000 ? '$' + (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k'
                      : '$' + Math.round(n);

const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const monthLabel = key => {
  const [y, m] = (key || '').split('-');
  return MONTH_NAMES[(+m || 1) - 1] + (m ? '' : '') + ' ’' + (y || '').slice(2);
};

/* ---------------------------------------------------------------- settings */
function initAccounts(onChange) {
  const inputs = $$('[data-broker]');
  if (!inputs.length) return () => ({});

  const saved = readAccounts();
  if (saved) inputs.forEach(el => {
    if (saved[el.dataset.broker] != null) el.value = saved[el.dataset.broker];
  });

  const totalEl = $('#acct-total'), fracEl = $('#acct-frac'), basisEl = $('#basis-note');
  // The three that hand back a fraction. Marked in the DOM so this list lives
  // in one place (playsfeed.FRACTIONAL_BROKERS) and is not restated here.
  const fracKeys = $$('.bslot').filter(s => $('.bn i', s)).map(s => $('[data-broker]', s).dataset.broker);

  const collect = () => {
    const map = {};
    inputs.forEach(el => { map[el.dataset.broker] = clamp(Math.floor(+el.value) || 0, 0, 99); });
    return map;
  };

  const sync = (persist) => {
    const map = collect();
    const total = Object.values(map).reduce((a, b) => a + b, 0);
    const frac = fracKeys.reduce((a, k) => a + (map[k] || 0), 0);
    if (totalEl) totalEl.textContent = total;
    if (fracEl) fracEl.textContent = frac;
    if (basisEl) {
      const used = Object.values(map).filter(Boolean).length;
      basisEl.innerHTML = `${total} account${total === 1 ? '' : 's'} across ${used} broker${used === 1 ? '' : 's'} · <label for="settings-open">change</label>`;
    }
    if (persist) writeAccounts(map);
    onChange(map);
  };

  inputs.forEach(el => el.addEventListener('input', () => sync(true), { passive: true }));
  sync(false);
  return collect;
}

/* ------------------------------------------------------------- the figures */

/* Broker key -> the name the settings panel shows. Read from the DOM rather
   than restated here, so the display names keep living in one place
   (playsfeed.SUPPORTED_BROKERS) and cannot drift out of step with it. */
function brokerNames() {
  const map = {};
  $$('.bslot').forEach(slot => {
    const input = $('[data-broker]', slot), name = $('.bn', slot);
    if (!input || !name) return;
    // .bn also carries an <i>◆</i> for the three that hold fractions; the
    // name is the text node in front of it.
    map[input.dataset.broker] = (name.firstChild?.textContent || name.textContent || '').trim();
  });
  return map;
}

function summarise(rows, accounts, month, names = {}) {
  const byMonth = new Map();
  const byBroker = new Map();
  const detail = [];
  let total = 0, plays = 0;

  rows.forEach(r => {
    const key = (r.on || '').slice(0, 7) || '—';
    if (month && key !== month) return;
    // THE RULE: only your accounts at the brokers this play was sold at. A
    // broker the sell alert never named contributes nothing, however many
    // accounts you hold there.
    const held = r.brokers.filter(k => (accounts[k] || 0) > 0);
    const n = held.reduce((a, k) => a + accounts[k], 0);
    if (!n) return;
    const amount = r.per * n;
    total += amount; plays += 1;
    detail.push({ sym: r.sym, on: r.on, per: r.per, held, n, amount });
    const bucket = byMonth.get(key) || { key, total: 0, plays: 0 };
    bucket.total += amount; bucket.plays += 1;
    byMonth.set(key, bucket);

    // The same money, split by WHERE it landed. This is a decomposition, not a
    // second estimate: summed over the brokers it comes back to `amount`, and
    // over the rows to `total`, exactly.
    held.forEach(k => {
      const b = byBroker.get(k) ||
        { key: k, name: names[k] || k, accounts: accounts[k], total: 0, plays: 0 };
      b.total += r.per * accounts[k];
      b.plays += 1;
      b.accounts = accounts[k];
      byBroker.set(k, b);
    });
  });

  const months = [...byMonth.values()].sort((a, b) => a.key < b.key ? -1 : 1);
  const brokers = [...byBroker.values()].sort((a, b) => b.total - a.total);
  const best = months.reduce((a, m) => (!a || m.total > a.total) ? m : a, null);
  detail.sort((a, b) => b.amount - a.amount);
  return { total, plays, months, brokers, best, detail,
           perMonth: months.length ? total / months.length : 0 };
}

/* --------------------------------------------------------------- the charts
   Hand-built SVG: no library, and none of the defaults a library brings.
   Thin marks, hairline axes, labels only where they earn their place.

   EVERY CHART DRAWS AT THE WIDTH OF ITS CARD — see boxWidth below. That keeps
   one type size across the dashboard whatever column a chart lands in, and it
   means every dimension in these functions is a real pixel.

   Colour never carries meaning alone: every outcome segment is named in a
   legend, every broker bar is named beside it, and both scales are labelled. */

const SVG_NS = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs = {}) => {
  const n = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
};

const WIDE = 620, NARROW = 400;
const EASE = 'cubic-bezier(.22,1,.36,1)';       // matches --ease

/* Draw at the width the card actually is.

   An SVG at width:100% scales its own text along with the box, so one fixed
   viewBox means 10px labels render at 6px in a phone-width card and at 26px in
   a full-bleed one. Taking the measured width as the viewBox width pins the
   scale at 1:1 everywhere, and every dimension below is then a real pixel.
   Falls back when the element has no box yet — a chart inside a tab nobody has
   opened measures zero. */
const boxWidth = (host, fallback) => {
  const w = Math.round(host.getBoundingClientRect().width);
  return w > 60 ? w : fallback;
};

/* Gradient/clip ids have to be unique per document or the second chart on the
   page silently paints itself with the first one's fill. */
let _defSeq = 0;
const uid = p => `${p}-${++_defSeq}`;

/* style= rather than stop-color=: a CSS variable in a presentation attribute
   is not portable, and these colours have to come from the token set. */
function linearGrad(id, stops, vertical = true) {
  const g = svgEl('linearGradient', vertical ? { id, x1: 0, y1: 0, x2: 0, y2: 1 }
                                             : { id, x1: 0, y1: 0, x2: 1, y2: 0 });
  stops.forEach(([off, color, op]) => g.appendChild(
    svgEl('stop', { offset: off, style: `stop-color:${color};stop-opacity:${op}` })));
  return g;
}

/* Exact, from the points — getTotalLength() on a path inside a hidden tab pane
   is unreliable, and this is a polyline, so the arithmetic is the same answer. */
const polyLength = pts => pts.reduce(
  (a, p, i) => i ? a + Math.hypot(p.x - pts[i - 1].x, p.y - pts[i - 1].y) : 0, 0);

/* Draw the stroke on, once. Repainting on every keystroke in the accounts
   panel would re-run this forty times while someone types "12". */
function drawStroke(paths, len, delay = .18) {
  paths.forEach(p => {
    p.style.strokeDasharray = len;
    p.style.strokeDashoffset = len;
  });
  requestAnimationFrame(() => paths.forEach(p => {
    p.style.transition = `stroke-dashoffset .95s ${EASE} ${delay}s`;
    p.style.strokeDashoffset = 0;
  }));
}

let _tip;
function tipFor(host) {
  if (!_tip) {
    _tip = document.createElement('div');
    _tip.className = 'charttip';
    document.body.appendChild(_tip);
  }
  return _tip;
}
function showTip(x, y, html) {
  const t = tipFor();
  t.innerHTML = html;
  t.style.left = x + 'px';
  t.style.top = y + 'px';
  t.classList.add('on');
}
const hideTip = () => _tip && _tip.classList.remove('on');

/* A "nice" axis ceiling, so ticks land on 1/2/5 x 10^n rather than 3,847. */
function niceMax(v) {
  if (v <= 0) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
}

function emptyChart(host, msg) {
  host.innerHTML = '';
  const p = document.createElement('p');
  p.className = 'empty-note';
  p.textContent = msg;
  host.appendChild(p);
}

/* ---------------------------------------------------------- profit by month
   One figure answering two questions: what each month paid (bars, left scale)
   and what the record was worth by the end of it (line, right scale).

   These were two cards side by side plotting the same series twice. Folded
   together they cost half the height, and "is this compounding or is it one
   good month?" is answerable in a glance instead of by holding one chart in
   your head while looking at the other.

   Both scales are anchored at zero across the same plot height, so the three
   gridlines are true for the left axis and the right one at once — the reason
   a dual axis is honest here and usually isn't. */
function profitChart(host, months) {
  if (!host) return;
  if (!months.length) return emptyChart(host, 'Nothing paid out in this period.');

  const W = boxWidth(host, WIDE), H = 232, L = 46, R = 46, T = 20, B = 26;
  const iw = W - L - R, ih = H - T - B;

  const max = niceMax(Math.max(...months.map(m => m.total)));
  let run = 0;
  const cum = months.map(m => (run += m.total));
  const cmax = niceMax(run);
  const avg = months.reduce((a, m) => a + m.total, 0) / months.length;

  // Cap the band and centre the group. Three months spread across the full
  // width leave two hairlines adrift in a field of nothing; grouped, they read
  // as a small chart rather than a broken one.
  const band = Math.min(iw / months.length, 108);
  const x0 = L + (iw - band * months.length) / 2;
  const bw = Math.min(26, band * .46);
  const cx = i => x0 + band * i + band / 2;
  const y = v => T + ih - (v / max) * ih;         // left scale:  the month
  const cy = v => T + ih - (v / cmax) * ih;       // right scale: the running total

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });
  const gBar = uid('bar'), gArea = uid('area');
  const defs = svgEl('defs');
  defs.appendChild(linearGrad(gBar, [[0, 'var(--c-series)', .98], [1, 'var(--c-series)', .28]]));
  defs.appendChild(linearGrad(gArea, [[0, 'var(--accent-2)', .28], [1, 'var(--accent-2)', 0]]));
  s.appendChild(defs);

  // Hover bands go down first so everything else paints over them.
  const bandLayer = svgEl('g');
  s.appendChild(bandLayer);

  // Recessive grid: three hairlines carrying both scales at once.
  [0, .5, 1].forEach(f => {
    const yy = y(max * f);
    s.appendChild(svgEl('line', { class: 'ax-line', x1: L, x2: W - R, y1: yy, y2: yy }));
    const l = svgEl('text', { class: 'ax-text', x: L - 8, y: yy + 3, 'text-anchor': 'end' });
    l.textContent = compact(max * f);
    s.appendChild(l);
    const r = svgEl('text', { class: 'ax-text run', x: W - R + 8, y: yy + 3 });
    r.textContent = compact(cmax * f);
    s.appendChild(r);
  });

  // The per-month average, drawn where the KPI tile only states it.
  if (months.length > 1) {
    const ay = y(avg);
    s.appendChild(svgEl('line', { class: 'ax-avg', x1: L, x2: W - R, y1: ay, y2: ay }));
    const t = svgEl('text', { class: 'ax-text avg', x: L + 3, y: ay - 5 });
    t.textContent = 'avg ' + compact(avg);
    s.appendChild(t);
  }

  const bars = months.map((m, i) => {
    const x = cx(i) - bw / 2;
    const h = Math.max(2, ih - (y(m.total) - T));
    const r = Math.min(5, bw / 2, h);
    // Rounded data-end, square at the baseline.
    const d = `M${x} ${T + ih}L${x} ${T + ih - h + r}Q${x} ${T + ih - h} ${x + r} ${T + ih - h}` +
              `L${x + bw - r} ${T + ih - h}Q${x + bw} ${T + ih - h} ${x + bw} ${T + ih - h + r}` +
              `L${x + bw} ${T + ih}Z`;
    const bar = svgEl('path', { class: 'mark-bar', d, style: `fill:url(#${gBar})` });
    s.appendChild(bar);
    return bar;
  });

  // The running total. A wide translucent copy under the crisp one reads as a
  // glow without an SVG filter, which would re-rasterise on every repaint.
  const pts = months.map((m, i) => ({ x: cx(i), y: cy(cum[i]) }));
  let strokes = [];
  if (pts.length > 1) {
    const line = pts.map(p => `${p.x} ${p.y}`).join('L');
    s.appendChild(svgEl('path', {
      class: 'mark-area', style: `fill:url(#${gArea})`,
      d: `M${pts[0].x} ${T + ih}L${line}L${pts[pts.length - 1].x} ${T + ih}Z`,
    }));
    const halo = svgEl('path', { class: 'mark-line halo', d: `M${line}` });
    const line2 = svgEl('path', { class: 'mark-line', d: `M${line}` });
    s.appendChild(halo); s.appendChild(line2);
    strokes = [halo, line2];
  }

  // End marker + the one direct label the line needs, set above the dot so it
  // never collides with the right-hand ticks.
  const last = pts[pts.length - 1];
  s.appendChild(svgEl('circle', { class: 'mark-dot', cx: last.x, cy: last.y, r: 4 }));
  const endLab = svgEl('text', { class: 'val-text', x: last.x, y: last.y - 10, 'text-anchor': 'middle' });
  endLab.textContent = compact(cum[cum.length - 1]);
  s.appendChild(endLab);

  // One roving dot, moved to whichever month the pointer is over.
  const live = svgEl('circle', { class: 'mark-dot live', cx: 0, cy: 0, r: 5 });
  s.appendChild(live);

  months.forEach((m, i) => {
    if (months.length <= 12 || i % 2 === 0) {
      const t = svgEl('text', { class: 'ax-text', x: cx(i), y: H - 8, 'text-anchor': 'middle' });
      t.textContent = monthLabel(m.key);
      s.appendChild(t);
    }

    const lit = svgEl('rect', {
      class: 'hoverband', x: x0 + band * i + 1.5, y: T - 8,
      width: band - 3, height: ih + 8, rx: 8,
    });
    bandLayer.appendChild(lit);

    // Hit areas last: transparent, on top, so the whole column is a target.
    const hit = svgEl('rect', { class: 'hit', x: x0 + band * i, y: T - 8, width: band, height: ih + 8 });
    hit.addEventListener('pointerenter', ev => {
      lit.classList.add('on');
      bars[i].classList.add('hot');
      live.setAttribute('cx', cx(i));
      live.setAttribute('cy', cy(cum[i]));
      live.classList.add('on');
      const r = ev.target.getBoundingClientRect();
      showTip(r.left + r.width / 2, r.top + 10,
        `${monthLabel(m.key)} · ${m.plays} play${m.plays === 1 ? '' : 's'}` +
        `<b>${money(m.total)}</b><i>running total ${money(cum[i])}</i>`);
    });
    hit.addEventListener('pointerleave', () => {
      lit.classList.remove('on');
      bars[i].classList.remove('hot');
      live.classList.remove('on');
      hideTip();
    });
    s.appendChild(hit);
  });

  host.appendChild(s);

  if (!REDUCED && !host.dataset.drawn) {
    bars.forEach((b, i) => { b.style.animationDelay = (i * 55) + 'ms'; b.classList.add('grow'); });
    if (strokes.length) drawStroke(strokes, polyLength(pts));
  }
  host.dataset.drawn = '1';
}

/* -------------------------------------------------------------- where it paid
   The hero figure, split by the broker the sell actually happened at. Not a
   second estimate of anything: summed down the rows it is the hero figure to
   the cent. It answers the one question the month chart cannot — which of YOUR
   accounts is carrying this — and it moves the instant the profile does.

   A broker you hold accounts at that no sell alert ever named is absent rather
   than drawn at zero: it earned nothing because nothing sold there, and a row
   of zeroes reads as a failure instead of a non-event. */
function brokerChart(host, brokers) {
  if (!host) return;
  if (!brokers.length) {
    return emptyChart(host, 'No sell alert in this period named a broker you hold.');
  }

  const W = boxWidth(host, NARROW), L = 96, R = 54, rowH = 23, bh = 11, T = 2;
  const H = brokers.length * rowH + T + 4;
  const iw = W - L - R;
  const max = Math.max(...brokers.map(b => b.total));

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });
  const g = uid('bgrad');
  const defs = svgEl('defs');
  defs.appendChild(linearGrad(g, [[0, 'var(--accent-2)', .9], [1, 'var(--c-series)', .95]], false));
  s.appendChild(defs);

  const bars = [];
  brokers.forEach((b, i) => {
    const y = T + i * rowH + 6;
    const w = Math.max(3, (b.total / max) * iw);

    const name = svgEl('text', { class: 'ax-text name', x: L - 10, y: y + bh - 1.5, 'text-anchor': 'end' });
    name.textContent = b.name;
    s.appendChild(name);

    // The track, so a small broker still reads as a share of something rather
    // than as a stub floating in space.
    s.appendChild(svgEl('rect', { class: 'track', x: L, y, width: iw, height: bh, rx: bh / 2 }));

    const bar = svgEl('rect', {
      class: 'mark-hbar', x: L, y, width: w, height: bh, rx: bh / 2,
      style: `fill:url(#${g})`,
    });
    s.appendChild(bar);
    bars.push(bar);

    const val = svgEl('text', { class: 'val-text', x: W - 2, y: y + bh - 1.5, 'text-anchor': 'end' });
    val.textContent = compact(b.total);
    s.appendChild(val);

    const hit = svgEl('rect', { class: 'hit', x: 0, y: y - 6, width: W, height: rowH });
    hit.addEventListener('pointerenter', ev => {
      bar.classList.add('hot');
      const r = ev.target.getBoundingClientRect();
      showTip(r.left + r.width / 2, r.top + 4,
        `${b.name} · ${b.accounts} account${b.accounts === 1 ? '' : 's'}` +
        `<b>${money(b.total)}</b><i>${b.plays} play${b.plays === 1 ? '' : 's'} sold here</i>`);
    });
    hit.addEventListener('pointerleave', () => { bar.classList.remove('hot'); hideTip(); });
    s.appendChild(hit);
  });

  host.appendChild(s);

  if (!REDUCED && !host.dataset.drawn) {
    bars.forEach((b, i) => { b.style.animationDelay = (i * 45) + 'ms'; b.classList.add('growx'); });
  }
  host.dataset.drawn = '1';
}

/* ------------------------------------------------------------- the hero spark
   The running total again, at thumbnail size, under the number it produced.
   No axes and no labels: it is a shape, not a reading, and the chart below
   carries the same series properly for anyone who wants the values. */
function heroSpark(host, months) {
  if (!host) return;
  host.innerHTML = '';
  if (months.length < 2) return;

  // Full-bleed: the band runs edge to edge across the foot of the card, so no
  // horizontal inset, and just enough top room that the stroke never clips.
  const W = boxWidth(host, 320), H = 46, TOP = 7;
  let run = 0;
  const cum = months.map(m => (run += m.total));
  const top = run || 1;
  const pts = cum.map((v, i) => ({
    x: W * (i / (cum.length - 1)),
    y: TOP + (H - TOP - 2) * (1 - v / top),
  }));

  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
  const g = uid('spark');
  const defs = svgEl('defs');
  defs.appendChild(linearGrad(g, [[0, 'var(--c-series)', .34], [1, 'var(--c-series)', 0]]));
  s.appendChild(defs);

  const line = pts.map(p => `${p.x} ${p.y}`).join('L');
  s.appendChild(svgEl('path', {
    class: 'spark-area', style: `fill:url(#${g})`,
    d: `M${pts[0].x} ${H}L${line}L${pts[pts.length - 1].x} ${H}Z`,
  }));
  const stroke = svgEl('path', { class: 'spark-line', d: `M${line}` });
  s.appendChild(stroke);
  // No end marker. The last point sits exactly on the card's right edge, where
  // a dot would be sliced in half by the clip and read as a rendering fault.

  host.appendChild(s);
  if (!REDUCED && !host.dataset.drawn) drawStroke([stroke], polyLength(pts), .1);
  host.dataset.drawn = '1';
}

/* ---------------------------------------------------------------- the count
   Counts the hero up on first paint and on a period change. A keystroke in
   the accounts panel sets it outright instead: animating a number the reader
   is actively steering makes it unreadable.

   tickTo, not a private rAF loop. Clicking two period chips in quick
   succession would start a second animation over the first, and two loops
   writing to one node make the total visibly count backwards — the exact
   failure the odometer above was built to cancel. Reusing it also inherits
   the retarget, which resumes from what is on screen instead of snapping
   back to zero. */
function heroCount(el, to, animate) {
  if (!el) return;
  if (REDUCED || !animate) { cancelTick(el); el.textContent = money(to); return; }
  tickTo(el, 0, to, 850, money);
}

/* ----------------------------------------------------------------- outcomes
   What every split the feed has ever carried actually DID, as one stacked bar
   with a named legend under it. It was four horizontal bars at 30px a row —
   the same four numbers, three times the height, and the reader still had to
   do the division to see that most of them round up.

   Read from the Tracking tab's own summary, which keeps one source of truth on
   the page. Colour is a second channel here, never the only one: every segment
   is named and counted in the legend, and the shares are printed. */
const OUTCOME_FILL = {
  rounded_up:   'var(--c-good)',
  fractional:   'var(--c-warn)',
  cash_in_lieu: 'rgba(184,137,43,.55)',
  pending:      'rgba(124,120,255,.5)',
  new:          'rgba(124,120,255,.5)',
};
const outcomeFill = s => OUTCOME_FILL[s] || 'var(--c-null)';

function outcomeChart(host) {
  if (!host) return;
  const src = $$('.statbar .sb');
  if (!src.length) return emptyChart(host, 'No outcomes recorded yet.');

  const rows = src.map(node => ({
    status: (node.className.match(/sb-([a-z_]+)/) || [, ''])[1],
    label: node.textContent.replace(/^\s*\d+\s*/, '').trim(),
    n: parseInt($('b', node)?.textContent || '0', 10),
  })).filter(r => r.n > 0).sort((a, b) => b.n - a.n);
  if (!rows.length) return emptyChart(host, 'No outcomes recorded yet.');

  const all = rows.reduce((a, r) => a + r.n, 0);
  // A 100% bar is a wide, short shape, so it gets the full page width and a
  // legend that wraps beside it rather than a column of rows underneath.
  const W = boxWidth(host, 1000), bh = 22, H = bh;

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });

  // One rounded clip over square segments: the bar keeps its pill ends without
  // every segment having to know whether it is an end.
  const clip = uid('clip');
  const defs = svgEl('defs');
  const cp = svgEl('clipPath', { id: clip });
  cp.appendChild(svgEl('rect', { x: 0, y: 0, width: W, height: bh, rx: bh / 2 }));
  defs.appendChild(cp);
  s.appendChild(defs);

  const stack = svgEl('g', { 'clip-path': `url(#${clip})` });
  s.appendChild(stack);

  let x = 0;
  rows.forEach((r, i) => {
    const w = (r.n / all) * W;
    const seg = svgEl('rect', {
      class: 'seg', x, y: 0, width: Math.max(0, w - (i === rows.length - 1 ? 0 : 1.5)),
      height: bh, style: `fill:${outcomeFill(r.status)}`,
    });
    stack.appendChild(seg);

    // The share, inside the segment, only where it fits without crowding.
    if (w > 74) {
      const t = svgEl('text', { class: 'seg-text', x: x + w / 2, y: bh / 2 + 3.5, 'text-anchor': 'middle' });
      t.textContent = Math.round((r.n / all) * 100) + '%';
      stack.appendChild(t);
    }

    const hit = svgEl('rect', { class: 'hit', x, y: 0, width: w, height: bh });
    hit.addEventListener('pointerenter', ev => {
      seg.classList.add('hot');
      const rect = ev.target.getBoundingClientRect();
      showTip(rect.left + rect.width / 2, rect.top,
        `${r.label}<b>${r.n} of ${all}</b><i>${((r.n / all) * 100).toFixed(1)}% of every alert</i>`);
    });
    hit.addEventListener('pointerleave', () => { seg.classList.remove('hot'); hideTip(); });
    s.appendChild(hit);

    x += w;
  });

  host.appendChild(s);

  // The legend in HTML, not SVG: it has to wrap at whatever width the card
  // ends up, and text that wraps is a job for the layout engine, not for
  // arithmetic that guesses where the line breaks.
  const legend = document.createElement('div');
  legend.className = 'chartkey';
  rows.forEach(r => {
    const item = document.createElement('span');
    item.className = 'ck';
    const sw = document.createElement('i');
    sw.style.background = outcomeFill(r.status);
    item.append(sw, r.label);
    const n = document.createElement('b');
    n.textContent = r.n;
    item.append(n);
    legend.appendChild(item);
  });
  host.appendChild(legend);

  if (!REDUCED && !host.dataset.drawn) stack.classList.add('growx');
  host.dataset.drawn = '1';
}

/* ------------------------------------------------------------ the dashboard */
function initPlaysDash() {
  const data = $('#payouts');
  if (!data) return;

  let rows = [];
  try { rows = JSON.parse(data.textContent || '[]'); } catch (e) { rows = []; }

  const heroTotal = $('#hero-total'), heroSub = $('#hero-sub'), heroPeriod = $('#hero-period');
  const heroSparkEl = $('#hero-spark');
  const kpiPer = $('#kpi-permonth'), kpiBest = $('#kpi-best'), kpiWhen = $('#kpi-best-when');
  // The month in progress, and the key the SERVER decided it is. Taking it
  // from the browser's own clock would let the tile and the page it sits in
  // land on different months for anyone whose date is a few hours off ours.
  const kpiThis = $('#kpi-thismonth'), kpiThisNote = $('#kpi-thismonth-note');
  const thisKey = $('#tile-thismonth')?.dataset.month || '';
  const monthly = $('#chart-monthly'), brokersEl = $('#chart-brokers');
  const tableBody = $('#monthly-table tbody');

  // The funnel's last stage is the only one that moves with the profile: the
  // three before it are counts of what the FEED did, which no account setting
  // can change. The bar is scaled against the same base the server used.
  const funnel = $('#funnel');
  const paidN = $('#fn-paid'), paidBar = $('#fn-paid-bar'), paidPct = $('#fn-paid-pct');
  const funnelBase = Math.max(0, parseInt(funnel?.dataset.base || '0', 10));

  const auditBody = $('#audit-table tbody');
  const names = brokerNames();
  let month = '';                      // '' = all time
  let accounts = {};
  let animate = true;

  const paint = () => {
    const s = summarise(rows, accounts, month, names);

    heroCount(heroTotal, s.total, animate);
    if (heroSub) {
      heroSub.textContent = s.plays
        ? `across ${s.plays} plays with a confirmed sell, in the brokers each one actually sold at`
        : 'no confirmed sell in this period landed in a broker you hold';
    }
    // Its own pass over the rows, scoped to the current month rather than to
    // the selected period: switching the chips must not change what this
    // month has made.
    if (kpiThis && thisKey) {
      const tm = summarise(rows, accounts, thisKey, names);
      kpiThis.textContent = money(tm.total);
      if (kpiThisNote) {
        kpiThisNote.textContent = tm.plays
          ? `${tm.plays} play${tm.plays === 1 ? '' : 's'} paid · ${thisKey}`
          : 'nothing booked yet';
      }
    }

    if (kpiPer) kpiPer.textContent = money(s.perMonth);
    if (kpiBest) kpiBest.textContent = s.best ? money(s.best.total) : '—';
    if (kpiWhen) kpiWhen.textContent = s.best ? s.best.key : '';

    if (tableBody) {
      tableBody.innerHTML = '';
      s.months.slice().reverse().forEach(m => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="mono">${m.key}</td><td class="mono">${m.plays}</td>` +
                       `<td class="mono pos">${money(m.total)}</td>`;
        tableBody.appendChild(tr);
      });
    }

    if (auditBody) {
      auditBody.innerHTML = '';
      s.detail.forEach(d => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          `<td class="mono dim">${d.on}</td><td><b>${d.sym}</b></td>` +
          `<td class="mono">${money(d.per)}</td>` +
          `<td class="small dim">${d.held.join(', ')}</td>` +
          `<td class="mono">${d.n}</td>` +
          `<td class="mono pos">${money(d.amount)}</td>`;
        auditBody.appendChild(tr);
      });
    }

    if (paidN) paidN.textContent = s.plays;
    // toFixed(1) to match the server's `| round(1)` exactly. Without it this
    // bar lands a few hundredths of a percent wider than the stage above it,
    // which is the one thing a funnel is not allowed to do.
    if (paidBar) {
      paidBar.style.width =
        (funnelBase ? (100 * s.plays / funnelBase).toFixed(1) : 0) + '%';
    }
    if (paidPct) {
      paidPct.textContent = funnelBase
        ? Math.round(100 * s.plays / funnelBase) + '% of alerts' : '';
    }

    profitChart(monthly, s.months);
    brokerChart(brokersEl, s.brokers);
    heroSpark(heroSparkEl, s.months);
    animate = false;
  };

  $$('#range-row .chip').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#range-row .chip').forEach(b => b.classList.toggle('on', b === btn));
      month = btn.dataset.month || '';
      if (heroPeriod) heroPeriod.textContent = month || 'all time';
      // A period change is a deliberate act and a whole new series, so let it
      // draw itself again. Typing in the accounts panel is not: that fires per
      // keystroke, and re-running the animation forty times is a strobe.
      [monthly, brokersEl, heroSparkEl].forEach(el => { if (el) delete el.dataset.drawn; });
      animate = true;
      paint();
    });
  });

  const collect = initAccounts(map => { accounts = map; paint(); });
  accounts = collect();
  outcomeChart($('#chart-outcomes'));
  paint();
  addEventListener('scroll', hideTip, { passive: true });

  // The charts draw at the width of the card, so a resize has to redraw them
  // or the type ends up scaled. Debounced, and past the animation gate, so a
  // dragged window edge is one repaint at the end and not a flicker of
  // bars growing out of the floor at sixty frames a second.
  let rz;
  addEventListener('resize', () => {
    clearTimeout(rz);
    rz = setTimeout(() => { paint(); outcomeChart($('#chart-outcomes')); }, 180);
  }, { passive: true });
}

/* ============================================================================
   "I BOUGHT THIS" — the reader's own marks
   ----------------------------------------------------------------------------
   Eleven open alerts look identical to someone who acted on four of them
   yesterday. A tick is how they tell those apart: everything unticked is what
   is left to buy, which is the question the Buys tab is opened to answer.

   Stored in localStorage and nowhere else. The board is behind one shared
   password — there is no account to hang a note on, and none of this is any of
   our business. The controls are hidden until this file runs (html.js, set at
   the top) rather than server-rendered and inert: a checkbox that forgets
   itself on reload is worse than none.

   Identity is `alert_date:SYMBOL`, matching playsfeed.PlayLife.key, and not a
   row id — the deploy runs an ephemeral database and re-ingests the feed, so
   ids move under a browser that is still holding notes about them.
   ========================================================================= */

const BOUGHT_STORE = 'rsamaxxed.bought.v1';
const HIDE_STORE = 'rsamaxxed.bought.hide';

function readBought() {
  try {
    const raw = JSON.parse(localStorage.getItem(BOUGHT_STORE) || 'null');
    return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
  } catch (e) { return {}; }        // blocked storage, private mode, corrupt
}

function writeBought(map) {
  try { localStorage.setItem(BOUGHT_STORE, JSON.stringify(map)); } catch (e) { /* fine */ }
}

function initBought() {
  const boxes = $$('.ownbox');
  if (!boxes.length) return;

  let marks = readBought();
  const stat = $('#mark-stat'), hideBtn = $('#mark-hide'), clearBtn = $('#mark-clear');
  const badge = $('#buys-badge');
  // Open plays only. The closed fold below the list renders the same rows, and
  // "how many are left to buy" must never count a window that has already shut.
  const openBoxes = $$('#open-plays .ownbox');
  const total = openBoxes.length;
  const exits = $$('.prow.exit[data-sym]');

  /* The payoff for ticking a box. When a sell alert lands for something the
     reader marked bought, the Sells tab says so instead of making them
     remember — which is the moment the money is actually made.

     Matched on ticker AND date: a mark carries the date it was alerted in its
     key, and an exit older than that belongs to the ticker's PREVIOUS reverse
     split. Flagging that would tell someone they hold a position they don't. */
  const markExits = () => {
    if (!exits.length) return;
    const held = new Map();               // SYMBOL -> earliest alert date marked
    boxes.forEach(box => {
      if (!marks[box.dataset.play]) return;
      const on = (box.dataset.play || '').split(':')[0] || '';
      (box.dataset.syms || '').split(',').forEach(raw => {
        const sym = raw.trim().toUpperCase();
        if (!sym) return;
        const prev = held.get(sym);
        if (prev === undefined || on < prev) held.set(sym, on);
      });
    });

    exits.forEach(li => {
      const from = held.get((li.dataset.sym || '').toUpperCase());
      const yours = from !== undefined && (li.dataset.sold || '') >= from;
      li.classList.toggle('held', yours);
      const tag = $('.ptag.you', li);
      if (yours && !tag) {
        const t = document.createElement('span');
        t.className = 'ptag you';
        t.textContent = 'You bought';
        $('.sym', li)?.after(t);
      } else if (!yours && tag) {
        tag.remove();
      }
    });
  };

  const paint = () => {
    // Every box is repainted from the store, which is what keeps the copies of
    // one play in sync: the same alert is drawn on the Buys tab, in the
    // calendar's day list and in "Closing next", and ticking one has to tick
    // its twins or the board disagrees with itself tab by tab.
    boxes.forEach(box => {
      box.checked = !!marks[box.dataset.play];
      box.closest('.prow')?.classList.toggle('bought', box.checked);
    });

    const done = openBoxes.filter(b => b.checked).length;
    const left = total - done;
    if (stat) {
      stat.innerHTML = done
        ? `<b>${left}</b> still to buy · ${done} marked bought`
        : `<b>${total}</b> open · tick the ones you have already bought`;
    }
    if (badge) {
      badge.textContent = left;
      badge.title = done ? `${left} of ${total} open plays not marked bought`
                         : `${total} open plays`;
    }
    if (clearBtn) clearBtn.hidden = !Object.keys(marks).length;
    markExits();
  };

  boxes.forEach(box => box.addEventListener('change', () => {
    const key = box.dataset.play;
    // The date it was ticked, not a flag: it costs nothing to keep and it is
    // the only thing that could ever say how stale a note is.
    if (box.checked) marks[key] = new Date().toISOString().slice(0, 10);
    else delete marks[key];
    writeBought(marks);
    paint();
  }));

  /* Hiding is a separate, deliberate act from marking — a ticked row still
     reads perfectly well dimmed, and someone who bought everything should not
     be shown an empty tab by default. Remembered, because a preference you
     have to set on every visit isn't one. */
  const setHide = (on, persist) => {
    document.documentElement.classList.toggle('hide-bought', on);
    hideBtn?.classList.toggle('on', on);
    hideBtn?.setAttribute('aria-pressed', String(on));
    if (persist) { try { localStorage.setItem(HIDE_STORE, on ? '1' : ''); } catch (e) { /* fine */ } }
  };
  let hidden = false;
  try { hidden = localStorage.getItem(HIDE_STORE) === '1'; } catch (e) { /* fine */ }
  setHide(hidden, false);
  hideBtn?.addEventListener('click', () =>
    setHide(!document.documentElement.classList.contains('hide-bought'), true));

  /* Clear arms on the first click and fires on the second. A window.confirm
     would do the same job, but a modal dialog for a note in localStorage is a
     heavier interruption than the thing it is protecting. */
  let armed = false;
  const disarm = () => {
    armed = false;
    if (clearBtn) { clearBtn.textContent = 'Clear marks'; clearBtn.classList.remove('armed'); }
  };
  clearBtn?.addEventListener('click', () => {
    if (!armed) {
      armed = true;
      clearBtn.textContent = 'Clear every mark — sure?';
      clearBtn.classList.add('armed');
      return;
    }
    marks = {};
    writeBought(marks);
    disarm();
    paint();
  });
  // Capture, so a click anywhere else takes the safety back off before that
  // click does whatever it was going to do.
  addEventListener('click', e => { if (armed && e.target !== clearBtn) disarm(); }, true);

  paint();
}

/* ============================================================================
   THE NEW-ALERT CHIME
   ----------------------------------------------------------------------------
   The board is a server-rendered snapshot: it draws once and never speaks to
   the server again, so on its own an open tab would never learn that an alert
   had landed. This is the only thing on the page that polls, and it earns that
   because a reverse-split buy window is measured in days and sometimes hours —
   somebody who leaves the tab open all day should not have to keep reloading it
   to find out whether there is anything to buy.

   Three constraints shaped every decision here:

     AUTOPLAY  a browser will not make a sound until the page has been clicked.
               So the chime is armed by a deliberate toggle rather than being on
               by default — an "on" that silently does nothing on first load is
               worse than an "off". The click that enables it IS the gesture
               that makes audio legal, which is why it plays once right there.
     CSP       default-src 'self' forbids a data: audio URI, so there is no
               sound FILE to serve, cache-bust or add a policy exception for.
               The cha-ching is synthesised in WebAudio.
     HONESTY   the chime does not redraw the board. Rewriting the page under
               someone who is reading it would be worse than the reload it
               saves, so it says what landed and offers the reload.

   The poll runs whether or not the sound is on: the toast and the tab-title
   badge are useful to someone who wants to be told quietly.
   ========================================================================= */

const SOUND_STORE = 'rsamaxxed.sound';
const POLL_MS = 60000;
const FEED_URL = '/api/v1/public/plays';

/* A cash register, from parts: a filtered noise transient for the drawer, then
   two bell strikes a fifth apart — the "cha" and the "CHING". The partials are
   deliberately inharmonic (x2.01, x2.99 rather than x2, x3); exact harmonics
   read as an organ, and struck metal never is. */
function chaChing(ctx) {
  const now = ctx.currentTime;
  const out = ctx.createGain();
  out.gain.value = 0.22;                    // quiet: this fires unprompted
  out.connect(ctx.destination);

  const noise = ctx.createBufferSource();
  const buf = ctx.createBuffer(1, Math.floor(ctx.sampleRate * 0.06), ctx.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < data.length; i++) {
    data[i] = (Math.random() * 2 - 1) * (1 - i / data.length);
  }
  noise.buffer = buf;
  const band = ctx.createBiquadFilter();
  band.type = 'bandpass';
  band.frequency.value = 2400;
  band.Q.value = 0.9;
  const ng = ctx.createGain();
  ng.gain.setValueAtTime(0.5, now);
  ng.gain.exponentialRampToValueAtTime(0.0001, now + 0.07);
  noise.connect(band).connect(ng).connect(out);
  noise.start(now);

  [[0, 1046.5, 0.42], [0.085, 1568.0, 0.9]].forEach(([at, hz, ring], strike) => {
    [1, 2.01, 2.99].forEach((mult, partial) => {
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = hz * mult;
      const gain = ctx.createGain();
      const t = now + at;
      const peak = (0.34 / (partial + 1)) * (strike ? 1.15 : 0.8);
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(peak, t + 0.006);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + ring);
      osc.connect(gain).connect(out);
      osc.start(t);
      osc.stop(t + ring + 0.05);
    });
  });
}

function initPlayAlerts() {
  const btn = $('#sound-toggle');
  if (!btn) return;                          // not the plays board
  const label = $('#sound-label');

  /* The baseline is the PAGE, not the first poll: the board renders exactly the
     open plays the feed holds, so anything the next poll knows that this page
     doesn't is genuinely new since it was opened. */
  const known = new Set($$('#open-plays .ownbox').map(b => b.dataset.play));
  const BASE_TITLE = document.title;
  let pending = 0;

  let ctx = null;
  const arm = () => {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!ctx && AC) ctx = new AC();
    // Chrome starts a context suspended when it isn't sure about the gesture.
    if (ctx && ctx.state === 'suspended') ctx.resume().catch(() => {});
    return ctx;
  };
  const ping = () => { try { if (arm()) chaChing(ctx); } catch (e) { /* no audio */ } };

  let soundOn = false;
  try { soundOn = localStorage.getItem(SOUND_STORE) === '1'; } catch (e) { /* fine */ }

  const paintToggle = () => {
    btn.classList.toggle('on', soundOn);
    btn.setAttribute('aria-pressed', String(soundOn));
    if (label) label.textContent = soundOn ? 'Chime on' : 'Chime off';
  };
  paintToggle();

  // A browser that already has permission from a previous visit still needs a
  // gesture in THIS one. The first click anywhere is enough, and costs nothing.
  if (soundOn) addEventListener('pointerdown', arm, { once: true, passive: true });

  btn.addEventListener('click', () => {
    soundOn = !soundOn;
    try { localStorage.setItem(SOUND_STORE, soundOn ? '1' : ''); } catch (e) { /* fine */ }
    paintToggle();
    if (soundOn) ping();                     // hear what you just agreed to
  });

  /* The tab title, so a chime from a background tab has something to point at.
     Cleared by a reload, which is the only thing that actually resolves it. */
  const setBadge = () => {
    document.title = pending ? `(${pending}) ${BASE_TITLE}` : BASE_TITLE;
  };

  const toast = symbols => {
    let host = $('#toast-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toast-host';
      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      document.body.appendChild(host);
    }
    host.innerHTML = '';                     // one toast, always the latest count

    const card = document.createElement('div');
    card.className = 'toast';

    const title = document.createElement('b');
    title.textContent = pending === 1 ? 'New alert' : `${pending} new alerts`;

    // textContent, not innerHTML: these strings come off the wire, and a
    // ticker is never worth an injection hole.
    const syms = document.createElement('span');
    syms.className = 'syms';
    syms.textContent = symbols.slice(0, 4).join(', ') + (symbols.length > 4 ? '…' : '');

    const show = document.createElement('button');
    show.type = 'button';
    show.className = 'btn btn-sm';
    show.textContent = 'Show';
    show.addEventListener('click', () => location.reload());

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'tclose';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '✕';
    close.addEventListener('click', () => host.remove());

    card.append(title, syms, show, close);
    host.appendChild(card);
  };

  const poll = () => {
    fetch(FEED_URL, { credentials: 'same-origin', cache: 'no-store',
                      headers: { Accept: 'application/json' } })
      .then(r => (r.ok ? r.json() : null))    // 401 = the gate expired. Stay quiet.
      .then(feed => {
        if (!feed) return;
        // The same identity the board and the "bought" marks use, so a play
        // cannot be new here and familiar three lines further down the page.
        const fresh = (feed.buys || [])
          .map(p => `${p.alert_date || ''}:${String(p.symbol || '').toUpperCase()}`)
          .filter(k => k !== ':' && !known.has(k));
        if (!fresh.length) return;
        fresh.forEach(k => known.add(k));
        pending += fresh.length;
        setBadge();
        toast(fresh.map(k => k.split(':')[1]));
        if (soundOn) ping();
      })
      .catch(() => { /* offline, or the tab was frozen. Try again next tick. */ });
  };

  setInterval(poll, POLL_MS);
}

/* ---------------------------------------------------------------- the pager
   Day-groups, N at a time. Everything is in the DOM already — this only sets
   `hidden` — so with the script blocked the tab is simply a long complete list
   rather than an empty one, and no exit is ever gated behind JavaScript. */
function initPager() {
  const pager = $('#exit-pager');
  if (!pager) return;
  const items = $$('.pgitem');
  const per = Math.max(1, parseInt(pager.dataset.per || '7', 10));
  const pages = Math.ceil(items.length / per);
  const stat = $('.pgstat', pager);
  if (pages < 2) { pager.hidden = true; return; }

  let page = 0;
  const draw = () => {
    items.forEach((it, i) => {
      it.hidden = Math.floor(i / per) !== page;
    });
    if (stat) stat.textContent = `Page ${page + 1} of ${pages}`;
    $$('.pgbtn', pager).forEach(b => {
      b.disabled = (b.dataset.page === 'prev' && page === 0) ||
                   (b.dataset.page === 'next' && page === pages - 1);
    });
  };

  $$('.pgbtn', pager).forEach(b => b.addEventListener('click', () => {
    page = clamp(page + (b.dataset.page === 'next' ? 1 : -1), 0, pages - 1);
    draw();
    pager.scrollIntoView({ block: 'nearest', behavior: REDUCED ? 'auto' : 'smooth' });
  }));

  draw();
}

/* ------------------------------------------------------------- the calendar
   Click a day to narrow the list beside it; click it again for everything.
   The list is entirely server-rendered, so with this file blocked the calendar
   is a static month view above a complete list — never an empty panel. */
function initPlaysCalendar() {
  const days = $$('button.cday');
  if (!days.length) return;
  const blocks = $$('.dayblock');
  const note = $('#day-filter-note');
  let picked = '';

  days.forEach(btn => btn.addEventListener('click', () => {
    picked = (picked === btn.dataset.day) ? '' : btn.dataset.day;
    days.forEach(b => b.classList.toggle('sel', b.dataset.day === picked));
    blocks.forEach(b => b.classList.toggle('hide', !!picked && b.dataset.day !== picked));
    if (note) note.textContent = picked ? `closing ${picked}` : 'every open play';
  }));
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
  initPlaysDash();
  initPlaysCalendar();
  initPager();
  initBought();
  initPlayAlerts();
}

if (document.readyState === 'loading') addEventListener('DOMContentLoaded', boot);
else boot();
