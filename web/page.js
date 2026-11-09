// Page behaviour shared by receipt.html (Proof Card) and index.html (verifier). Plain JS, no framework.
(function () {
  var C = window.AttestedCore;
  var $ = function (s, r) { return (r || document).querySelector(s); };

  function theme() {
    var b = document.getElementById('theme');
    if (!b) return;
    try { var t = localStorage.getItem('attested-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}
    b.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      var next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('attested-theme', next); } catch (e) {}
    });
  }

  function copyButtons(root) {
    (root || document).querySelectorAll('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () {
        var v = b.getAttribute('data-copy');
        var done = function () { var o = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = o; }, 1200); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(v).then(done, function () {});
      });
    });
  }

  function renderRecheck(out, res) {
    var rows = res.results.map(function (c) {
      return '<div class="row"><div class="pillcell">' + C.pill(c.status) + '</div><div><div class="t">' + C.esc(c.label) + '</div><div class="d">' + C.esc(c.detail) + '</div></div></div>';
    }).join('');
    var head = res.ok
      ? '<div class="notice"><strong>Result: OK.</strong> The receipt is intact and its evidence re-verifies in this page, offline.</div>'
      : '<div class="notice warn"><strong>Result: INVALID.</strong> The receipt does not verify. Do not trust it.</div>';
    out.innerHTML = head + '<div class="group">' + rows + '</div>';
  }

  async function recheck(receipt, out) {
    if (!(window.crypto && crypto.subtle)) { out.innerHTML = '<div class="notice warn">This browser context has no WebCrypto (crypto.subtle). Open the file in a current browser, or use the command line.</div>'; return; }
    out.innerHTML = '<div class="notice">Re-checking...</div>';
    try {
      var res = await C.verifyReceipt(receipt, { verifySig: null });
      renderRecheck(out, res);
    } catch (e) {
      out.innerHTML = '<div class="notice warn"><strong>Could not verify:</strong> ' + C.esc(e.message) + '</div>';
    }
  }

  theme();
  copyButtons(document);

  var data = document.getElementById('receipt-data');
  var btn = document.getElementById('recheck');
  if (btn && data) {
    btn.addEventListener('click', function () {
      var r; try { r = JSON.parse(data.textContent); } catch (e) { return; }
      recheck(r, document.getElementById('recheck-out'));
    });
  }

  // verifier page (index.html): paste or drop a receipt
  var drop = document.getElementById('drop');
  if (drop) {
    var view = document.getElementById('view');
    var sample = data ? data.textContent : null;
    var show = async function (text, initial) {
      var r;
      try { r = JSON.parse(text); } catch (e) { view.innerHTML = '<div class="notice warn"><strong>Not valid JSON.</strong> ' + C.esc(e.message) + '</div>'; return; }
      var res;
      try { res = await C.verifyReceipt(r, { verifySig: null }); } catch (e) { view.innerHTML = '<div class="notice warn"><strong>Could not verify:</strong> ' + C.esc(e.message) + '</div>'; return; }
      var card = '';
      try { card = C.renderCard(r, { verifyUi: false }); } catch (e) { card = '<div class="notice warn">This file verifies as JSON but is not a renderable receipt: ' + C.esc(e.message) + '</div>'; }
      view.innerHTML = '<section class="card" id="result"><h2>Verification result</h2><p class="lede">' + (initial ? 'Sample receipt from the recorded demo. ' : '') + 'Computed just now, in this page, offline.</p><div class="out" id="res-out"></div></section>' + card;
      renderRecheck(document.getElementById('res-out'), res);
      copyButtons(view);
      var el = document.getElementById('result'); if (!initial && el && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
    var ta = document.getElementById('paste');
    document.getElementById('go').addEventListener('click', function () { show(ta.value); });
    var tamper = document.getElementById('tamper');
    if (tamper && sample) {
      tamper.addEventListener('click', function () {
        // flip one character inside the model id, then verify: must fail
        var t = sample.replace('"id": "Qwen', '"id": "Pwen').replace('"id":"Qwen', '"id":"Pwen');
        ta.value = t.slice(0, 400) + '...';
        show(t);
      });
    }
    var load = document.getElementById('load-sample');
    if (load && sample) load.addEventListener('click', function () { ta.value = ''; show(sample); });
    if (sample) show(sample, true);
    var file = document.getElementById('file');
    file.addEventListener('change', function () { if (file.files[0]) file.files[0].text().then(show); });
    ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
    drop.addEventListener('drop', function (e) { var f = e.dataTransfer.files[0]; if (f) f.text().then(show); });
  }
})();
