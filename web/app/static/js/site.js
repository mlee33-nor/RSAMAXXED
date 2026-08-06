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
function summarise(rows, accounts, monthsBack) {
  let cutoff = '';
  if (monthsBack > 0) {
    const d = new Date();
    d.setMonth(d.getMonth() - monthsBack);
    cutoff = d.toISOString().slice(0, 10);
  }

  const byMonth = new Map();
  let total = 0, plays = 0;
  rows.forEach(r => {
    if (cutoff && (r.on || '') < cutoff) return;
    // The rule: only accounts at the brokers this play actually paid in.
    const n = r.brokers.reduce((a, k) => a + (accounts[k] || 0), 0);
    if (!n) return;
    const amount = r.per * n;
    total += amount; plays += 1;
    const key = (r.on || '').slice(0, 7) || '—';
    const bucket = byMonth.get(key) || { key, total: 0, plays: 0 };
    bucket.total += amount; bucket.plays += 1;
    byMonth.set(key, bucket);
  });

  const months = [...byMonth.values()].sort((a, b) => a.key < b.key ? -1 : 1);
  const best = months.reduce((a, m) => (!a || m.total > a.total) ? m : a, null);
  return { total, plays, months, best, perMonth: months.length ? total / months.length : 0 };
}

/* --------------------------------------------------------------- the charts
   Hand-built SVG: no library, and none of the defaults a library brings.
   Thin marks, hairline axes, one hue per chart, labels only where they earn
   their place — the value on the tallest column, the value at the end of the
   line, and the count at the tip of each outcome bar. */

const SVG_NS = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs = {}) => {
  const n = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
};

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

function monthlyChart(host, months) {
  if (!host) return;
  if (!months.length) return emptyChart(host, 'Nothing paid out in this period.');

  const W = 620, H = 200, L = 52, R = 10, T = 16, B = 28;
  const iw = W - L - R, ih = H - T - B;
  const max = niceMax(Math.max(...months.map(m => m.total)));
  const band = iw / months.length;
  const bw = Math.min(24, band * 0.55);          // cap the mark; leftover is air
  const y = v => T + ih - (v / max) * ih;

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });

  // Recessive grid: three solid hairlines, and the ticks that carry the values
  // no bar is directly labelled with.
  [0, .5, 1].forEach(f => {
    const yy = y(max * f);
    s.appendChild(svgEl('line', { class: 'ax-line', x1: L, x2: W - R, y1: yy, y2: yy }));
    const t = svgEl('text', { class: 'ax-text', x: L - 8, y: yy + 3, 'text-anchor': 'end' });
    t.textContent = compact(max * f);
    s.appendChild(t);
  });

  const peak = months.reduce((a, m) => m.total > a.total ? m : a, months[0]);

  months.forEach((m, i) => {
    const x = L + band * i + (band - bw) / 2;
    const h = Math.max(1, ih - (y(m.total) - T));
    const r = Math.min(4, bw / 2, h);
    // Rounded data-end, square at the baseline.
    const d = `M${x} ${T + ih}L${x} ${T + ih - h + r}Q${x} ${T + ih - h} ${x + r} ${T + ih - h}` +
              `L${x + bw - r} ${T + ih - h}Q${x + bw} ${T + ih - h} ${x + bw} ${T + ih - h + r}` +
              `L${x + bw} ${T + ih}Z`;

    const hit = svgEl('rect', { class: 'hit', x: L + band * i, y: T, width: band, height: ih });
    const bar = svgEl('path', { class: 'mark-bar', d });
    hit.addEventListener('pointerenter', ev => {
      bar.classList.add('hot');
      const r2 = ev.target.getBoundingClientRect();
      showTip(r2.left + r2.width / 2, r2.top + (y(m.total) - T) * (r2.height / ih),
        `${monthLabel(m.key)} · ${m.plays} play${m.plays === 1 ? '' : 's'}<b>${money(m.total)}</b>`);
    });
    hit.addEventListener('pointerleave', () => { bar.classList.remove('hot'); hideTip(); });
    s.appendChild(hit);
    s.appendChild(bar);

    // Label selectively: the peak carries its value, the axis carries the rest.
    if (m === peak && h > 14) {
      const t = svgEl('text', { class: 'val-text', x: x + bw / 2, y: y(m.total) - 6, 'text-anchor': 'middle' });
      t.textContent = compact(m.total);
      s.appendChild(t);
    }

    if (months.length <= 10 || i % 2 === 0) {
      const t = svgEl('text', { class: 'ax-text', x: x + bw / 2, y: H - 9, 'text-anchor': 'middle' });
      t.textContent = monthLabel(m.key);
      s.appendChild(t);
    }
  });

  host.appendChild(s);
}

function cumulativeChart(host, months) {
  if (!host) return;
  if (months.length < 2) return emptyChart(host, 'Two months of payouts are needed to draw a trend.');

  const W = 620, H = 200, L = 52, R = 42, T = 16, B = 28;
  const iw = W - L - R, ih = H - T - B;
  let run = 0;
  const pts = months.map((m, i) => {
    run += m.total;
    return { x: L + (iw * i) / (months.length - 1), y: 0, v: run, key: m.key };
  });
  const max = niceMax(run);
  pts.forEach(p => { p.y = T + ih - (p.v / max) * ih; });

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });

  [0, .5, 1].forEach(f => {
    const yy = T + ih - f * ih;
    s.appendChild(svgEl('line', { class: 'ax-line', x1: L, x2: W - R, y1: yy, y2: yy }));
    const t = svgEl('text', { class: 'ax-text', x: L - 8, y: yy + 3, 'text-anchor': 'end' });
    t.textContent = compact(max * f);
    s.appendChild(t);
  });

  const line = pts.map(p => `${p.x} ${p.y}`).join('L');
  s.appendChild(svgEl('path', {
    class: 'mark-area',
    d: `M${pts[0].x} ${T + ih}L${line}L${pts[pts.length - 1].x} ${T + ih}Z`,
  }));
  s.appendChild(svgEl('path', { class: 'mark-line', d: `M${line}` }));

  pts.forEach((p, i) => {
    if (months.length <= 10 || i % 2 === 0) {
      const t = svgEl('text', { class: 'ax-text', x: p.x, y: H - 9, 'text-anchor': 'middle' });
      t.textContent = monthLabel(p.key);
      s.appendChild(t);
    }
    const hit = svgEl('circle', { class: 'hit', cx: p.x, cy: p.y, r: 14 });
    hit.addEventListener('pointerenter', ev => {
      const r = ev.target.getBoundingClientRect();
      showTip(r.left + r.width / 2, r.top, `${monthLabel(p.key)} · running total<b>${money(p.v)}</b>`);
    });
    hit.addEventListener('pointerleave', hideTip);
    s.appendChild(hit);
  });

  // End marker + the one direct label the line needs.
  const last = pts[pts.length - 1];
  s.appendChild(svgEl('circle', { class: 'mark-dot', cx: last.x, cy: last.y, r: 4.5 }));
  const lab = svgEl('text', { class: 'val-text', x: last.x + 9, y: last.y + 4 });
  lab.textContent = compact(last.v);
  s.appendChild(lab);

  host.appendChild(s);
}

/* Outcomes. Status colours, and every bar carries its name and count as text —
   so the categories never depend on colour to be told apart. Read from the
   Tracking tab's own summary, which keeps one source of truth on the page. */
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

  const fill = s => s === 'rounded_up' ? 'var(--c-good)'
    : (s === 'fractional' || s === 'cash_in_lieu') ? 'var(--c-warn)' : 'var(--c-null)';

  const W = 620, L = 150, R = 52, rowH = 30, bh = 14;
  const H = rows.length * rowH + 8;
  const max = Math.max(...rows.map(r => r.n));
  const iw = W - L - R;

  host.innerHTML = '';
  const s = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' });

  rows.forEach((r, i) => {
    const y = i * rowH + 8;
    const w = Math.max(2, (r.n / max) * iw);
    const rad = Math.min(4, w / 2);

    const name = svgEl('text', { class: 'ax-text', x: L - 12, y: y + bh - 2, 'text-anchor': 'end' });
    name.textContent = r.label;
    s.appendChild(name);

    // style= rather than fill=: a CSS variable in a presentation attribute is
    // not portable, and these colours have to come from the token set.
    s.appendChild(svgEl('path', {
      style: `fill:${fill(r.status)}`,
      d: `M${L} ${y}L${L + w - rad} ${y}Q${L + w} ${y} ${L + w} ${y + rad}` +
         `L${L + w} ${y + bh - rad}Q${L + w} ${y + bh} ${L + w - rad} ${y + bh}L${L} ${y + bh}Z`,
    }));

    const val = svgEl('text', { class: 'val-text', x: L + w + 9, y: y + bh - 2 });
    val.textContent = r.n;
    s.appendChild(val);
  });

  host.appendChild(s);
}

/* ------------------------------------------------------------ the dashboard */
function initPlaysDash() {
  const data = $('#payouts');
  if (!data) return;

  let rows = [];
  try { rows = JSON.parse(data.textContent || '[]'); } catch (e) { rows = []; }

  const heroTotal = $('#hero-total'), heroSub = $('#hero-sub'), heroPeriod = $('#hero-period');
  const kpiPer = $('#kpi-permonth'), kpiBest = $('#kpi-best'), kpiWhen = $('#kpi-best-when');
  const monthly = $('#chart-monthly'), cumulative = $('#chart-cumulative');
  const tableBody = $('#monthly-table tbody');

  let range = 0;                       // 0 = all time
  let accounts = {};

  const paint = () => {
    const s = summarise(rows, accounts, range);

    if (heroTotal) heroTotal.textContent = money(s.total);
    if (heroSub) {
      heroSub.textContent = s.plays
        ? `if you had bought all ${s.plays} plays the tracker says paid`
        : 'no split in this period paid into the accounts you hold';
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

    monthlyChart(monthly, s.months);
    cumulativeChart(cumulative, s.months);
  };

  $$('#range-row .chip').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#range-row .chip').forEach(b => b.classList.toggle('on', b === btn));
      range = parseInt(btn.dataset.range, 10) || 0;
      if (heroPeriod) {
        heroPeriod.textContent = range ? `last ${range} months` : 'all time';
      }
      paint();
    });
  });

  const collect = initAccounts(map => { accounts = map; paint(); });
  accounts = collect();
  outcomeChart($('#chart-outcomes'));
  paint();
  addEventListener('scroll', hideTip, { passive: true });
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
}

if (document.readyState === 'loading') addEventListener('DOMContentLoaded', boot);
else boot();
