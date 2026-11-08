// 메디가이드 화면 동작: 메뉴, 표(검색·필터·쪽 나누기), 팝업, AI 답변 스트리밍, 정적분석 진행 표시
(function () {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  // ── 메뉴 ───────────────────────────────
  $$('[data-group]').forEach(g => g.addEventListener('click', () => g.parentElement.classList.toggle('open')));
  const ham = $('[data-toggle-nav]');
  if (ham) ham.addEventListener('click', () => {
    if (window.innerWidth <= 900) document.body.classList.toggle('navopen');
    else document.body.classList.toggle('collapsed');
  });
  const um = $('[data-usermenu]');
  if (um) {
    um.addEventListener('click', e => { e.stopPropagation(); $('.usermenu', um).classList.toggle('open'); });
    document.addEventListener('click', () => $('.usermenu', um).classList.remove('open'));
  }

  // ── 표: 검색·필터·쪽 나누기 ─────────────────
  function setupTable(box) {
    const rows = $$('tbody tr[data-row]', box);
    const search = $('[data-dt-search]', box);
    const filters = $$('[data-dt-filter]', box);
    const pager = $('[data-pager]', box);
    const pp = pager ? $('[data-pp]', pager) : null;
    const state = { page: 1, kpi: null };
    const tbody = $('tbody', box);
    const emptyRow = document.createElement('tr');
    const ncol = $$('thead th', box).length || 1;
    emptyRow.innerHTML = `<td class="empty" colspan="${ncol}">표시할 항목이 없습니다.</td>`;

    function match(r) {
      const q = search ? search.value.trim().toLowerCase() : '';
      if (q && !(r.dataset.search || r.textContent).toLowerCase().includes(q)) return false;
      for (const f of filters) {
        const v = f.value; if (!v) continue;
        if ((r.dataset['f' + cap(f.dataset.dtFilter)] || '') !== v) return false;
      }
      if (state.kpi) {
        const [k, v] = state.kpi;
        if (v && (r.dataset['f' + cap(k)] || '') !== v) return false;
      }
      return true;
    }
    function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
    function render() {
      const vis = rows.filter(match);
      const per = pp ? parseInt(pp.value, 10) : 1e9;
      const pages = Math.max(1, Math.ceil(vis.length / per));
      state.page = Math.min(state.page, pages);
      rows.forEach(r => r.style.display = 'none');
      vis.slice((state.page - 1) * per, state.page * per).forEach(r => r.style.display = '');
      if (!vis.length) tbody.appendChild(emptyRow); else if (emptyRow.parentNode) emptyRow.remove();
      if (pager) {
        const a = vis.length ? (state.page - 1) * per + 1 : 0, b = Math.min(state.page * per, vis.length);
        $('[data-range]', pager).textContent = `${a}–${b} of ${vis.length}`;
        const pg = $('[data-pages]', pager); pg.innerHTML = '';
        const mk = (label, p, dis, on) => { const bt = document.createElement('button'); bt.type = 'button'; bt.innerHTML = label;
          bt.disabled = dis; if (on) bt.className = 'on'; bt.onclick = () => { state.page = p; render(); }; pg.appendChild(bt); };
        mk('‹', state.page - 1, state.page === 1);
        for (let i = 1; i <= pages; i++) if (pages <= 7 || Math.abs(i - state.page) <= 2 || i === 1 || i === pages) mk(String(i), i, false, i === state.page);
        mk('›', state.page + 1, state.page === pages);
      }
    }
    if (search) search.addEventListener('input', () => { state.page = 1; render(); });
    filters.forEach(f => f.addEventListener('change', () => { state.page = 1; render(); }));
    if (pp) pp.addEventListener('change', () => { state.page = 1; render(); });
    const reset = $('[data-dt-reset]', box);
    const kpiWrap = box.dataset.kpis ? $(box.dataset.kpis) : null;
    if (kpiWrap) $$('[data-kpi]', kpiWrap).forEach(k => k.addEventListener('click', () => {
      const [col, val] = k.dataset.kpi.split(':');
      $$('[data-kpi]', kpiWrap).forEach(x => x.classList.remove('sel'));
      if (val) { k.classList.add('sel'); state.kpi = [col, val]; } else state.kpi = null;
      state.page = 1; render();
    }));
    if (reset) reset.addEventListener('click', () => {
      if (search) search.value = ''; filters.forEach(f => f.value = ''); state.kpi = null;
      if (kpiWrap) $$('[data-kpi]', kpiWrap).forEach(x => x.classList.remove('sel'));
      state.page = 1; render();
    });
    box._render = render;
    render();
  }
  $$('[data-dt]').forEach(setupTable);

  // 행 클릭 이동
  document.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-href]');
    if (tr && !e.target.closest('a,button,input,select,form')) location.href = tr.dataset.href;
  });

  // ── 팝업 ───────────────────────────────
  const modalBg = $('#modal'), modalBox = $('#modal-box');
  window.openModal = function (html, size) {
    modalBox.className = 'modal' + (size ? ' ' + size : '');
    modalBox.innerHTML = html; modalBg.classList.add('open');
    $$('[data-ai-run]', modalBox).forEach(bindAi);
    $$('[data-autostart]', modalBox).forEach(b => b.click());
  };
  window.closeModal = function () { modalBg.classList.remove('open'); modalBox.innerHTML = ''; };
  if (modalBg) {
    modalBg.addEventListener('click', e => { if (e.target === modalBg || e.target.closest('[data-close]')) closeModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
  }
  document.addEventListener('click', async e => {
    const t = e.target.closest('[data-modal-url]');
    if (t && !e.target.closest('a,button:not([data-modal-url]),input,select')) {
      const r = await fetch(t.dataset.modalUrl); openModal(await r.text(), t.dataset.modalSize || '');
      return;
    }
    const s = e.target.closest('[data-modal-tpl]');
    if (s) { const tpl = $(s.dataset.modalTpl); openModal(tpl.innerHTML, s.dataset.modalSize || ''); }
  });

  // ── AI 답변 스트리밍 ────────────────────────
  const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const fmt = s => esc(s).replace(/\[(\d+)\]/g, '<span class="cite">$1</span>');
  window.renderAnswer = function (box, data) {
    const ans = $('.ai-ans', box), src = $('.ai-src', box);
    ans.innerHTML = data.not_found ? '<span style="color:#b26a00">' + esc(data.final) + '</span>' : fmt(data.final);
    if (src && data.hits) src.innerHTML = data.hits.length ? '<details><summary>근거 원문 보기 (' + data.hits.length + '건)</summary>' +
      data.hits.map((h, i) => `<div class="s"><b>[${i + 1}]</b>${esc(h.org)} · ${esc(h.title)}, ${h.page}쪽<span class="t">${esc(h.text)}</span></div>`).join('') + '</details>' : '';
  };
  async function aiStream(url, body, box) {
    const ans = $('.ai-ans', box); ans.innerHTML = '<span class="spin"></span> 규제 문서에서 근거를 찾는 중...';
    let text = '', hits = [];
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = '';
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i; while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1); if (!line.trim()) continue;
          const m = JSON.parse(line);
          if (m.hits) { hits = m.hits; ans.innerHTML = '<span class="spin"></span> 근거 ' + hits.length + '건을 바탕으로 답변을 작성하는 중...'; }
          if (m.d) { text += m.d; ans.innerHTML = fmt(text); }
          if (m.final !== undefined) renderAnswer(box, { final: m.final, not_found: m.not_found, hits });
          if (m.error) ans.innerHTML = '<span style="color:#c62828">' + esc(m.error) + '</span>';
        }
      }
    } catch (err) { ans.innerHTML = '<span style="color:#c62828">AI 답변을 가져오지 못했습니다: ' + esc(String(err)) + '</span>'; }
  }
  window.aiStream = aiStream;
  function bindAi(btn) {
    btn.addEventListener('click', () => {
      const box = $(btn.dataset.aiRun);
      box.hidden = false; btn.disabled = true;
      aiStream(btn.dataset.url, JSON.parse(btn.dataset.body || '{}'), box).finally(() => { btn.disabled = false; });
    });
  }
  $$('[data-ai-run]').forEach(bindAi);

  // ── 정적분석 진행 표시 ──────────────────────
  $$('[data-scan-poll]').forEach(el => {
    const code = el.dataset.scanPoll;
    const tick = async () => {
      const r = await fetch('/api/scans/' + code + '/steps'); const j = await r.json();
      el.innerHTML = j.html;
      if (j.status !== '진행중') { setTimeout(() => location.reload(), 900); return; }
      setTimeout(tick, 1200);
    };
    setTimeout(tick, 800);
  });

  // ── 파일 끌어놓기 ────────────────────────
  $$('[data-dropzone]').forEach(z => {
    const input = $('input[type=file]', z.closest('form')), label = $('[data-dz-label]', z), btn = $('[data-dz-submit]', z.closest('form'));
    z.addEventListener('click', () => input.click());
    ['dragenter', 'dragover'].forEach(ev => z.addEventListener(ev, e => { e.preventDefault(); z.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => z.addEventListener(ev, e => { e.preventDefault(); z.classList.remove('drag'); }));
    z.addEventListener('drop', e => { input.files = e.dataTransfer.files; input.dispatchEvent(new Event('change')); });
    input.addEventListener('change', () => {
      if (input.files.length) { label.textContent = input.files[0].name + ' (' + Math.round(input.files[0].size / 1024) + ' KB)'; if (btn) btn.disabled = false; }
    });
  });

  // 증빙 파일 선택 시 바로 올리기
  $$('[data-autosubmit]').forEach(i => i.addEventListener('change', () => i.form.submit()));
  // 확인 후 제출
  document.addEventListener('submit', e => { const m = e.target.dataset.confirm; if (m && !confirm(m)) e.preventDefault(); });
  // 영역 접기
  $$('.area > .ah').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('closed')));
})();
