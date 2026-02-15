import * as pdfjsLib from './vendor/pdfjs/pdf.min.mjs';

(function () {
  const api = window.RuaeApi;

  const BASE_PATH = '/maths';

  function toApiAssetUrl(input) {
    const raw = String(input || '').trim();
    if (!raw) return '';
    if (raw.startsWith('http://') || raw.startsWith('https://')) return raw;

    const base = api && typeof api.getApiBase === 'function' ? String(api.getApiBase() || '') : '';
    if (!base) return raw;

    if (raw.startsWith('/')) return `${base}${raw}`;
    return `${base}/${raw}`;
  }

  pdfjsLib.GlobalWorkerOptions.workerSrc = `${BASE_PATH}/vendor/pdfjs/pdf.worker.min.mjs`;
  const PDFJS_OPTIONS = {
    cMapUrl: `${BASE_PATH}/vendor/pdfjs/cmaps/`,
    cMapPacked: true,
    standardFontDataUrl: `${BASE_PATH}/vendor/pdfjs/standard_fonts/`,
    // Keep pdf.js requests "simple" (no Range preflights) and rely on full-file fetches.
    // This avoids CORS complexity for credentialed cross-origin requests to api.rishisubjects.co.uk.
    disableRange: true,
    disableStream: true,
    disableAutoFetch: true,
  };

  const yearSelect = document.getElementById('yearSelect');
  const paperSelect = document.getElementById('paperSelect');
  const searchInput = document.getElementById('searchInput');
  const datasheetBtn = document.getElementById('datasheetBtn');
  const diagnosticsLink = document.getElementById('diagnosticsLink');
  const logoutBtn = document.getElementById('logoutBtn');
  const sessionUsernameEl = document.getElementById('sessionEmail');
  const statusEl = document.getElementById('status');
  const routeEl = document.getElementById('route');
  const modalRoot = document.getElementById('modalRoot');

  let session = { authenticated: false, approved: false, user: null };
  let catalog = {
    years: [],
    questions: [],
  };

  let active = {
    year: 'all',
    paper: 'all',
    search: '',
    questionIds: [],
    questionIndexById: new Map(),
    question: null,
    showAnswer: false,
    datasheet: {
      open: false,
      year: null,
      paper: null,
      fileId: null,
      pdfUrl: '',
      pageCount: 0,
      doc: null,
      pageIndex: 0,
      zoom: 1,
      title: 'Datasheet',
      renderToken: 0,
    },
  };

  const pdfDocCache = new Map(); // fileId -> Promise<PDFDocumentProxy>

  function setStatus(message, level) {
    statusEl.textContent = message || '';
    statusEl.className = `status ${level || ''}`;
  }

  function isTypingTarget(target) {
    if (!target) return false;
    const tag = String(target.tagName || '').toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || target.isContentEditable;
  }

  function encodeNextPath() {
    const next = `${window.location.pathname}${window.location.search}`;
    return encodeURIComponent(next);
  }

  function loginUrl() {
    return `/login/?next=${encodeNextPath()}`;
  }

  function parseQuery() {
    const params = new URLSearchParams(window.location.search || '');
    const year = params.get('year') || 'all';
    const paper = params.get('paper') || 'all';
    const search = params.get('q') || '';

    active.year = /^\d{4}$/.test(year) ? year : 'all';
    active.paper = paper === '1' || paper === '2' ? paper : 'all';
    active.search = String(search || '');
  }

  function syncQueryToUrl() {
    const params = new URLSearchParams();
    if (active.year !== 'all') params.set('year', active.year);
    if (active.paper !== 'all') params.set('paper', active.paper);
    if (active.search.trim()) params.set('q', active.search.trim());

    const query = params.toString();
    const nextUrl = query ? `${BASE_PATH}?${query}` : `${BASE_PATH}`;
    window.history.replaceState({}, '', nextUrl);
  }

  function routePath() {
    const pathname = window.location.pathname || '';
    if (pathname === BASE_PATH) return '/';
    if (pathname === `${BASE_PATH}/`) return '/';
    if (pathname.startsWith(`${BASE_PATH}/`)) {
      return pathname.slice(BASE_PATH.length);
    }
    return '/';
  }

  function navigate(path) {
    const normalized = String(path || '').startsWith('/') ? path : `/${path}`;
    window.history.pushState({}, '', `${BASE_PATH}${normalized}`);
    render();
  }

  function onLinkClick(event) {
    const anchor = event.target && event.target.closest ? event.target.closest('a') : null;
    if (!anchor) return;
    const href = anchor.getAttribute('href') || '';
    if (!href.startsWith(`${BASE_PATH}/`) && href !== BASE_PATH && href !== `${BASE_PATH}?`) return;
    if (anchor.target && anchor.target !== '_self') return;
    event.preventDefault();
    const url = new URL(href, window.location.origin);
    window.history.pushState({}, '', url.pathname + url.search);
    render();
  }

  async function requireApprovedSession() {
    if (!api) {
      setStatus('Auth client failed to load.', 'error');
      return false;
    }

    const { response, data } = await api.apiRequest('/api/auth/me');

    if (!response.ok || !data.authenticated) {
      window.location.href = loginUrl();
      return false;
    }

    if (!data.approved) {
      session = { authenticated: true, approved: false, user: data.user || null };
      if (session.user && (session.user.username || session.user.email)) {
        sessionUsernameEl.textContent = session.user.username || session.user.email;
      }
      setStatus('Your account is pending approval.', 'error');
      routeEl.innerHTML = '';
      return false;
    }

    session = { authenticated: true, approved: true, user: data.user || null };
    if (session.user && (session.user.username || session.user.email)) {
      sessionUsernameEl.textContent = session.user.username || session.user.email;
    }

    return true;
  }

  async function apiGet(path) {
    const { response, data } = await api.apiRequest(path);
    if (response.status === 401 || response.status === 403) {
      window.location.href = loginUrl();
      return null;
    }
    if (!response.ok) {
      throw new Error(data.error || 'Request failed.');
    }
    return data;
  }

  async function loadPdfDocument(url) {
    const pdfUrl = toApiAssetUrl(url);
    if (!pdfUrl) throw new Error('Missing PDF URL.');
    const task = pdfjsLib.getDocument({
      url: pdfUrl,
      withCredentials: true,
      ...PDFJS_OPTIONS,
    });
    return await task.promise;
  }

  async function renderPdfPageToCanvas(doc, pageNumber, scale, canvas) {
    const page = await doc.getPage(pageNumber);
    const viewport = page.getViewport({ scale });
    const width = Math.max(1, Math.floor(viewport.width));
    const height = Math.max(1, Math.floor(viewport.height));

    canvas.width = width;
    canvas.height = height;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext('2d', { alpha: false });
    await page.render({ canvasContext: ctx, viewport }).promise;
    return { page, viewport };
  }

  async function getPdfDocForFile(file, filesById) {
    const fileId = typeof file === 'string' ? file : file && file.id;
    const id = String(fileId || '').trim();
    if (!id) throw new Error('Missing file id.');

    if (pdfDocCache.has(id)) {
      return await pdfDocCache.get(id);
    }

    let pdfUrl = '';
    if (typeof file === 'object' && file && typeof file.pdfUrl === 'string') {
      pdfUrl = file.pdfUrl;
    } else if (filesById && filesById.has(id)) {
      pdfUrl = String(filesById.get(id).pdfUrl || '');
    } else {
      const data = await apiGet(`/api/maths/file?id=${encodeURIComponent(id)}`);
      pdfUrl = String(data && data.file && data.file.pdfUrl || '');
    }

    const promise = loadPdfDocument(pdfUrl);
    pdfDocCache.set(id, promise);
    return await promise;
  }

  async function loadYears() {
    const data = await apiGet('/api/maths/years');
    if (!data) return;

    catalog.years = Array.isArray(data.years) ? data.years : [];

    yearSelect.innerHTML = '';
    const allOption = document.createElement('option');
    allOption.value = 'all';
    allOption.textContent = 'All years';
    yearSelect.appendChild(allOption);

    catalog.years
      .slice()
      .sort((a, b) => Number(b) - Number(a))
      .forEach((year) => {
        const option = document.createElement('option');
        option.value = String(year);
        option.textContent = String(year);
        yearSelect.appendChild(option);
      });

    yearSelect.value = active.year;
  }

  async function loadQuestions() {
    const params = new URLSearchParams();
    if (active.year !== 'all') params.set('year', active.year);
    if (active.paper !== 'all') params.set('paper', active.paper);
    if (active.search.trim()) params.set('q', active.search.trim());
    const data = await apiGet(`/api/maths/questions?${params.toString()}`);
    if (!data) return;

    const items = Array.isArray(data.questions) ? data.questions : [];
    catalog.questions = items;

    active.questionIds = items.map((q) => q.id);
    active.questionIndexById = new Map();
    active.questionIds.forEach((id, idx) => {
      active.questionIndexById.set(id, idx);
    });
  }

  function paperLabel(paperNumber) {
    if (String(paperNumber) === '1') return 'Paper 1 (Non-Calculator)';
    if (String(paperNumber) === '2') return 'Paper 2 (Calculator)';
    return 'All papers';
  }

  function buildListView() {
    const wrapper = document.createElement('div');
    wrapper.dataset.testid = 'maths-list-view';

    const heading = document.createElement('div');
    heading.className = 'panel';

    const title = document.createElement('h2');
    title.textContent = 'SQA Maths Past Paper Question Bank';

    const meta = document.createElement('div');
    meta.className = 'card-meta';
    meta.textContent = `${active.year === 'all' ? 'All years' : active.year} · ${paperLabel(active.paper)} · ${catalog.questions.length} question(s)`;

    heading.appendChild(title);
    heading.appendChild(meta);
    wrapper.appendChild(heading);

    const grid = document.createElement('div');
    grid.className = 'cards';
    grid.dataset.testid = 'maths-question-cards';

    if (!catalog.questions.length) {
      const empty = document.createElement('div');
      empty.className = 'panel';
      empty.textContent = 'No questions found for these filters.';
      wrapper.appendChild(empty);
      return wrapper;
    }

    catalog.questions.forEach((q) => {
      const a = document.createElement('a');
      a.href = `${BASE_PATH}/q/${encodeURIComponent(q.id)}`;
      a.className = 'card';
      a.dataset.testid = `maths-question-card-${q.id}`;
      a.dataset.questionId = String(q.id || '');

      const title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = q.qLabel || `Question ${q.qNumber || ''}`.trim();

      const meta = document.createElement('div');
      meta.className = 'card-meta';
      const topic = q.topic ? ` · ${q.topic}` : '';
      meta.textContent = `${q.year} · ${paperLabel(q.paperNumber)}${topic}`;

      const thumb = document.createElement('div');
      thumb.className = 'card-thumb';

      if (q.thumbUrl) {
        const img = document.createElement('img');
        img.loading = 'lazy';
        img.decoding = 'async';
        img.alt = q.qLabel || 'Question thumbnail';
        img.src = toApiAssetUrl(q.thumbUrl);
        thumb.appendChild(img);
      } else {
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = 'No thumbnail';
        thumb.appendChild(badge);
      }

      a.appendChild(title);
      a.appendChild(meta);
      a.appendChild(thumb);
      grid.appendChild(a);
    });

    wrapper.appendChild(grid);

    return wrapper;
  }

  function cropImg(src, alt) {
    const img = document.createElement('img');
    img.className = 'crop-img';
    img.alt = alt || 'Crop image';
    img.loading = 'lazy';
    img.decoding = 'async';
    img.src = toApiAssetUrl(src);
    return img;
  }

  function appendPdfCrop(wrapper, crop, alt, options) {
    const canvas = document.createElement('canvas');
    canvas.className = 'crop-img';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', alt || 'Crop image');
    canvas.width = 2;
    canvas.height = 2;
    wrapper.appendChild(canvas);

    const renderScale = Number(options && options.scale) > 0 ? Number(options.scale) : 2;

    queueMicrotask(async () => {
      try {
        const doc = await getPdfDocForFile(String(crop.fileId));
        const offscreen = document.createElement('canvas');
        const pageNumber = Number(crop.pageIndex) + 1;
        const { viewport } = await renderPdfPageToCanvas(doc, pageNumber, renderScale, offscreen);

        const rectViewport = viewport.convertToViewportRectangle([Number(crop.x0), Number(crop.y0), Number(crop.x1), Number(crop.y1)]);
        const left = Math.min(rectViewport[0], rectViewport[2]);
        const top = Math.min(rectViewport[1], rectViewport[3]);
        const width = Math.abs(rectViewport[2] - rectViewport[0]);
        const height = Math.abs(rectViewport[3] - rectViewport[1]);

        const sx = clamp(Math.floor(left), 0, offscreen.width - 1);
        const sy = clamp(Math.floor(top), 0, offscreen.height - 1);
        const sw = clamp(Math.floor(width), 1, offscreen.width - sx);
        const sh = clamp(Math.floor(height), 1, offscreen.height - sy);

        canvas.width = sw;
        canvas.height = sh;

        const ctx = canvas.getContext('2d', { alpha: false });
        ctx.drawImage(offscreen, sx, sy, sw, sh, 0, 0, sw, sh);
      } catch (error) {
        console.error('Crop render failure', error);
        wrapper.textContent = 'Unable to render crop.';
      }
    });
  }

  function cropFromPdfOrImg(crop, alt, options = {}) {
    const wrapper = document.createElement('div');
    wrapper.className = 'crop-wrap';

    const hasPdfCoords = crop
      && crop.fileId
      && Number.isFinite(Number(crop.pageIndex))
      && [crop.x0, crop.y0, crop.x1, crop.y1].every((v) => Number.isFinite(Number(v)));

    if (crop && crop.url) {
      const img = cropImg(crop.url, alt);
      img.addEventListener(
        'error',
        () => {
          // If the PNG crop is missing (or storage is misconfigured), fall back to rendering from the source PDF.
          wrapper.innerHTML = '';
          if (!hasPdfCoords) {
            wrapper.textContent = 'Crop unavailable.';
            return;
          }
          appendPdfCrop(wrapper, crop, alt, options);
        },
        { once: true }
      );
      wrapper.appendChild(img);
      return wrapper;
    }

    if (!hasPdfCoords) {
      wrapper.textContent = 'Crop unavailable.';
      return wrapper;
    }

    appendPdfCrop(wrapper, crop, alt, options);

    return wrapper;
  }

  function buildDetailView(question) {
    const wrapper = document.createElement('div');
    wrapper.dataset.testid = 'maths-detail-view';

    const header = document.createElement('div');
    header.className = 'panel';

    const title = document.createElement('h2');
    title.textContent = question.qLabel || `Question ${question.qNumber || ''}`.trim();

    const meta = document.createElement('div');
    meta.className = 'card-meta';
    meta.textContent = `${question.year} · ${paperLabel(question.paperNumber)}${question.topic ? ` · ${question.topic}` : ''}`;

    const actions = document.createElement('div');
    actions.className = 'actions-row';

    const back = document.createElement('button');
    back.type = 'button';
    back.className = 'secondary';
    back.textContent = 'Back to list';
    back.addEventListener('click', () => navigate('/'));

    const answerBtn = document.createElement('button');
    answerBtn.type = 'button';
    answerBtn.dataset.testid = 'maths-toggle-answer';
    answerBtn.textContent = active.showAnswer ? 'Hide answer (A)' : 'Show answer (A)';
    answerBtn.addEventListener('click', () => {
      active.showAnswer = !active.showAnswer;
      render();
    });

    const reviewBtn = document.createElement('button');
    reviewBtn.type = 'button';
    reviewBtn.className = 'secondary';
    reviewBtn.dataset.testid = 'maths-open-review';
    reviewBtn.textContent = 'Review (R)';
    reviewBtn.addEventListener('click', () => {
      navigate(`/review/${encodeURIComponent(question.id)}`);
    });

    actions.appendChild(back);
    actions.appendChild(answerBtn);
    actions.appendChild(reviewBtn);

    header.appendChild(title);
    header.appendChild(meta);
    header.appendChild(actions);

    wrapper.appendChild(header);

    const detail = document.createElement('div');
    detail.className = 'detail';

    const qPanel = document.createElement('div');
    qPanel.className = 'panel';

    const qTitle = document.createElement('h3');
    qTitle.textContent = 'Question';
    qPanel.appendChild(qTitle);

    const qStack = document.createElement('div');
    qStack.className = 'crop-stack';
    qStack.dataset.testid = 'maths-question-crops';

    (question.questionCrops || []).forEach((crop, idx) => {
      qStack.appendChild(cropFromPdfOrImg(crop, `Question crop ${idx + 1}`));
    });

    if (!qStack.children.length) {
      qStack.textContent = 'No question crops available.';
    }

    qPanel.appendChild(qStack);

    const aPanel = document.createElement('div');
    aPanel.className = 'panel';

    const aTitle = document.createElement('h3');
    aTitle.textContent = 'Answer';
    aPanel.appendChild(aTitle);

    const aStack = document.createElement('div');
    aStack.className = `crop-stack ${active.showAnswer ? '' : 'hidden'}`;
    aStack.dataset.testid = 'maths-answer-crops';

    (question.answerCrops || []).forEach((crop, idx) => {
      aStack.appendChild(cropFromPdfOrImg(crop, `Answer crop ${idx + 1}`));
    });

    if (!aStack.children.length) {
      aStack.textContent = 'No answer crops available.';
    }

    aPanel.appendChild(aStack);

    detail.appendChild(qPanel);
    detail.appendChild(aPanel);
    wrapper.appendChild(detail);

    return wrapper;
  }

  function buildDiagnosticsView(data) {
    const wrapper = document.createElement('div');

    const panel = document.createElement('div');
    panel.className = 'panel';

    const title = document.createElement('h2');
    title.textContent = 'Diagnostics';

    const items = document.createElement('div');
    items.className = 'card-meta';

    const lines = [];
    lines.push(`Files: ${data.files || 0}`);
    lines.push(`Questions: ${data.questions || 0}`);
    lines.push(`Crops: ${data.crops || 0}`);
    lines.push(`Datasheets: ${data.datasheets || 0}`);
    lines.push(`Missing mappings: ${data.missingMappings || 0}`);

    items.textContent = lines.join(' \u00b7 ');

    const logsPanel = document.createElement('div');
    logsPanel.className = 'panel';

    const logsTitle = document.createElement('h3');
    logsTitle.textContent = 'Last Pipeline Logs';

    const pre = document.createElement('pre');
    pre.style.whiteSpace = 'pre-wrap';
    pre.style.color = '#bdc7d8';
    pre.textContent = data.lastLogTail || 'No logs available.';

    logsPanel.appendChild(logsTitle);
    logsPanel.appendChild(pre);

    panel.appendChild(title);
    panel.appendChild(items);

    wrapper.appendChild(panel);
    wrapper.appendChild(logsPanel);

    return wrapper;
  }

  function clamp(value, min, max) {
    if (!Number.isFinite(value)) return min;
    return Math.min(max, Math.max(min, value));
  }

  function exportCanvasCropPngDataUrl(sourceCanvas, rect) {
    const sx = Math.max(0, Math.floor(rect.left));
    const sy = Math.max(0, Math.floor(rect.top));
    const sw = Math.max(1, Math.floor(rect.width));
    const sh = Math.max(1, Math.floor(rect.height));

    const out = document.createElement('canvas');
    out.width = sw;
    out.height = sh;
    const ctx = out.getContext('2d', { alpha: false });
    ctx.drawImage(sourceCanvas, sx, sy, sw, sh, 0, 0, sw, sh);
    return out.toDataURL('image/png');
  }

  function makeRectEl() {
    const rect = document.createElement('div');
    rect.className = 'rect';

    const dirs = ['nw', 'n', 'ne', 'e', 'se', 's', 'sw', 'w'];
    dirs.forEach((dir) => {
      const h = document.createElement('div');
      h.className = `handle handle-${dir}`;
      h.dataset.dir = dir;
      rect.appendChild(h);
    });

    return rect;
  }

  function buildReviewView(question, context) {
    const wrapper = document.createElement('div');
    wrapper.dataset.testid = 'maths-review-view';

    const filesById = context && context.filesById ? context.filesById : new Map();
    const pastPaperFiles = context && Array.isArray(context.pastPaperFiles) ? context.pastPaperFiles : [];
    const markSchemeFiles = context && Array.isArray(context.markSchemeFiles) ? context.markSchemeFiles : [];

    const review = {
      cropEditors: new Map(), // cropId -> editor
    };

    const panel = document.createElement('div');
    panel.className = 'panel';

    const title = document.createElement('h2');
    title.textContent = `Review: ${question.qLabel || question.id}`;

    const meta = document.createElement('div');
    meta.className = 'card-meta';
    meta.textContent = `${question.year} · ${paperLabel(question.paperNumber)} · Question ${question.qNumber}`;

    const form = document.createElement('div');
    form.className = 'review-form';

    const labelWrap = document.createElement('label');
    labelWrap.className = 'control grow';
    const labelSpan = document.createElement('span');
    labelSpan.className = 'label';
    labelSpan.textContent = 'Label';
    const labelInput = document.createElement('input');
    labelInput.type = 'text';
    labelInput.value = question.qLabel || '';
    labelInput.maxLength = 140;
    labelWrap.appendChild(labelSpan);
    labelWrap.appendChild(labelInput);

    const topicWrap = document.createElement('label');
    topicWrap.className = 'control';
    const topicSpan = document.createElement('span');
    topicSpan.className = 'label';
    topicSpan.textContent = 'Topic';
    const topicInput = document.createElement('input');
    topicInput.type = 'text';
    topicInput.value = question.topic || '';
    topicInput.maxLength = 120;
    topicWrap.appendChild(topicSpan);
    topicWrap.appendChild(topicInput);

    form.appendChild(labelWrap);
    form.appendChild(topicWrap);

    const actions = document.createElement('div');
    actions.className = 'actions-row';

    const back = document.createElement('button');
    back.type = 'button';
    back.className = 'secondary';
    back.textContent = 'Back';
    back.addEventListener('click', () => navigate(`/q/${encodeURIComponent(question.id)}`));

    const save = document.createElement('button');
    save.type = 'button';
    save.dataset.testid = 'maths-review-save';
    save.textContent = 'Save Review';

    actions.appendChild(back);
    actions.appendChild(save);

    panel.appendChild(title);
    panel.appendChild(meta);
    panel.appendChild(form);
    panel.appendChild(actions);

    wrapper.appendChild(panel);

    function addCropEditor(crop, kindLabel) {
      const cropPanel = document.createElement('div');
      cropPanel.className = 'panel crop-editor';

      const heading = document.createElement('div');
      heading.className = 'editor-heading';

      const hTitle = document.createElement('h3');
      const page = Number(crop.pageIndex) + 1;
      hTitle.textContent = `${kindLabel} · Page ${page}`;

      heading.appendChild(hTitle);

      const canvasWrap = document.createElement('div');
      canvasWrap.className = 'pdf-wrap';

      const canvas = document.createElement('canvas');
      canvas.className = 'pdf-canvas';

      const rectEl = makeRectEl();
      canvasWrap.appendChild(canvas);
      canvasWrap.appendChild(rectEl);

      const preview = document.createElement('img');
      preview.className = 'review-preview';
      preview.alt = `${kindLabel} preview`;
      preview.loading = 'lazy';
      preview.decoding = 'async';
      preview.src = toApiAssetUrl(crop.url || '');

      cropPanel.appendChild(heading);
      cropPanel.appendChild(canvasWrap);
      cropPanel.appendChild(preview);

      const editor = {
        cropId: crop.id,
        kind: kindLabel.toLowerCase(),
        crop,
        fileId: crop.fileId,
        pageIndex: Number(crop.pageIndex),
        renderScale: 2,
        canvas,
        rectEl,
        viewport: null,
        rectPx: null,
        dirty: false,
        preview,
        exportPngDataUrl() {
          if (!this.rectPx) return '';
          return exportCanvasCropPngDataUrl(this.canvas, this.rectPx);
        },
        getPdfRect() {
          if (!this.viewport || !this.rectPx) return null;
          const left = this.rectPx.left;
          const top = this.rectPx.top;
          const right = this.rectPx.left + this.rectPx.width;
          const bottom = this.rectPx.top + this.rectPx.height;
          const [xA, yA] = this.viewport.convertToPdfPoint(left, top);
          const [xB, yB] = this.viewport.convertToPdfPoint(right, bottom);
          return {
            x0: Math.min(xA, xB),
            y0: Math.min(yA, yB),
            x1: Math.max(xA, xB),
            y1: Math.max(yA, yB),
          };
        },
      };

      function setRect(rect) {
        editor.rectPx = rect;
        rectEl.style.left = `${rect.left}px`;
        rectEl.style.top = `${rect.top}px`;
        rectEl.style.width = `${rect.width}px`;
        rectEl.style.height = `${rect.height}px`;
      }

      function markDirty() {
        if (editor.dirty) return;
        editor.dirty = true;
        cropPanel.classList.add('dirty');
      }

      // Load and render PDF page.
      queueMicrotask(async () => {
        try {
          const fileMeta = filesById.get(editor.fileId) || null;
          const doc = await getPdfDocForFile(fileMeta || editor.fileId, filesById);
          const { viewport } = await renderPdfPageToCanvas(doc, editor.pageIndex + 1, editor.renderScale, canvas);
          editor.viewport = viewport;

          const rectViewport = viewport.convertToViewportRectangle([crop.x0, crop.y0, crop.x1, crop.y1]);
          const left = Math.min(rectViewport[0], rectViewport[2]);
          const top = Math.min(rectViewport[1], rectViewport[3]);
          const width = Math.abs(rectViewport[2] - rectViewport[0]);
          const height = Math.abs(rectViewport[3] - rectViewport[1]);

          setRect({
            left: clamp(left, 0, canvas.width),
            top: clamp(top, 0, canvas.height),
            width: clamp(width, 10, canvas.width),
            height: clamp(height, 10, canvas.height),
          });
        } catch (error) {
          console.error('Review render failure', error);
          cropPanel.appendChild(document.createTextNode('Unable to render PDF page.'));
        }
      });

      let drag = null;
      function onPointerDown(event) {
        if (!editor.rectPx || !editor.viewport) return;
        const dir = event.target && event.target.dataset ? event.target.dataset.dir : '';
        const mode = dir ? 'resize' : 'move';
        drag = {
          mode,
          dir: dir || '',
          startX: event.clientX,
          startY: event.clientY,
          startRect: { ...editor.rectPx },
        };
        rectEl.setPointerCapture(event.pointerId);
        event.preventDefault();
      }

      function onPointerMove(event) {
        if (!drag || !editor.rectPx) return;
        const dx = event.clientX - drag.startX;
        const dy = event.clientY - drag.startY;

        const boundsW = canvas.width;
        const boundsH = canvas.height;
        const minSize = 10;

        let { left, top, width, height } = drag.startRect;

        if (drag.mode === 'move') {
          left = clamp(left + dx, 0, boundsW - width);
          top = clamp(top + dy, 0, boundsH - height);
        } else {
          const right = left + width;
          const bottom = top + height;

          let nextLeft = left;
          let nextTop = top;
          let nextRight = right;
          let nextBottom = bottom;

          if (drag.dir.includes('w')) nextLeft = clamp(left + dx, 0, right - minSize);
          if (drag.dir.includes('n')) nextTop = clamp(top + dy, 0, bottom - minSize);
          if (drag.dir.includes('e')) nextRight = clamp(right + dx, nextLeft + minSize, boundsW);
          if (drag.dir.includes('s')) nextBottom = clamp(bottom + dy, nextTop + minSize, boundsH);

          left = nextLeft;
          top = nextTop;
          width = nextRight - nextLeft;
          height = nextBottom - nextTop;
        }

        setRect({ left, top, width, height });
        markDirty();
      }

      function onPointerUp(event) {
        if (!drag) return;
        drag = null;
        rectEl.releasePointerCapture(event.pointerId);
        // Update preview lazily on interaction end.
        if (editor.rectPx) {
          try {
            editor.preview.src = editor.exportPngDataUrl();
          } catch (error) {
            console.error('Preview export failure', error);
          }
        }
      }

      rectEl.addEventListener('pointerdown', onPointerDown);
      rectEl.addEventListener('pointermove', onPointerMove);
      rectEl.addEventListener('pointerup', onPointerUp);
      rectEl.addEventListener('pointercancel', onPointerUp);

      review.cropEditors.set(editor.cropId, editor);
      wrapper.appendChild(cropPanel);
    }

    (question.questionCrops || []).forEach((crop) => addCropEditor(crop, 'Question'));
    (question.answerCrops || []).forEach((crop) => addCropEditor(crop, 'Answer'));

    save.addEventListener('click', async () => {
      save.disabled = true;
      setStatus('Saving review...', '');
      try {
        const crops = [];
        for (const editor of review.cropEditors.values()) {
          if (!editor.dirty) continue;
          const pdfRect = editor.getPdfRect();
          if (!pdfRect) continue;
          const dataUrl = editor.exportPngDataUrl();
          crops.push({
            id: editor.cropId,
            x0: pdfRect.x0,
            y0: pdfRect.y0,
            x1: pdfRect.x1,
            y1: pdfRect.y1,
            imageBase64: dataUrl,
            contentType: 'image/png',
          });
        }

        const payload = {
          questionId: question.id,
          question: {
            qLabel: labelInput.value,
            topic: topicInput.value,
          },
          crops,
        };

        const { response, data } = await api.apiRequest('/api/maths/review/save', {
          method: 'POST',
          csrf: true,
          json: payload,
        });
        if (!response.ok) {
          throw new Error(data.error || 'Unable to save review.');
        }

        setStatus('Review saved.', 'ok');
        navigate(`/q/${encodeURIComponent(question.id)}`);
      } catch (error) {
        console.error('Review save failure', error);
        setStatus(error.message || 'Unable to save review.', 'error');
      } finally {
        save.disabled = false;
      }
    });

    return wrapper;
  }

  function closeModal() {
    modalRoot.innerHTML = '';
  }

  async function renderDatasheetModalPage(token) {
    const ds = active.datasheet;
    if (!ds.open || ds.renderToken !== token) return;
    const canvas = modalRoot.querySelector('canvas[data-role=\"datasheet\"]');
    if (!canvas || !ds.doc) return;
    const pageNumber = Math.min(Math.max(1, ds.pageIndex + 1), ds.pageCount || 1);
    await renderPdfPageToCanvas(ds.doc, pageNumber, ds.zoom, canvas);
    const label = modalRoot.querySelector('[data-role=\"ds-page-label\"]');
    if (label) {
      label.textContent = `${pageNumber} / ${ds.pageCount || 0}`;
    }
  }

  function openDatasheetModal() {
    const ds = active.datasheet;
    ds.renderToken += 1;
    const token = ds.renderToken;
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.dataset.testid = 'maths-modal-backdrop';
    backdrop.addEventListener('click', (event) => {
      if (event.target === backdrop) {
        ds.open = false;
        ds.doc = null;
        closeModal();
      }
    });

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.dataset.testid = 'maths-datasheet-modal';

    const header = document.createElement('header');

    const title = document.createElement('div');
    title.className = 'modal-title';
    title.dataset.testid = 'maths-datasheet-title';
    title.textContent = ds.title || 'Datasheet';

    const controls = document.createElement('div');
    controls.className = 'zoom-row';

    const prev = document.createElement('button');
    prev.type = 'button';
    prev.className = 'secondary';
    prev.textContent = 'Prev';
    prev.disabled = !ds.pageCount || ds.pageIndex <= 0;
    prev.addEventListener('click', () => {
      ds.pageIndex = Math.max(0, ds.pageIndex - 1);
      openDatasheetModal();
    });

    const next = document.createElement('button');
    next.type = 'button';
    next.className = 'secondary';
    next.textContent = 'Next';
    next.disabled = !ds.pageCount || ds.pageIndex >= ds.pageCount - 1;
    next.addEventListener('click', () => {
      ds.pageIndex = Math.min(Math.max(0, ds.pageCount - 1), ds.pageIndex + 1);
      openDatasheetModal();
    });

    const pageLabel = document.createElement('span');
    pageLabel.className = 'badge';
    pageLabel.setAttribute('data-role', 'ds-page-label');
    pageLabel.textContent = ds.pageCount ? `${ds.pageIndex + 1} / ${ds.pageCount}` : '—';

    const zoomOut = document.createElement('button');
    zoomOut.type = 'button';
    zoomOut.className = 'secondary';
    zoomOut.textContent = '-';
    zoomOut.addEventListener('click', () => {
      ds.zoom = Math.max(0.5, Math.round((ds.zoom - 0.1) * 10) / 10);
      render();
    });

    const zoomIn = document.createElement('button');
    zoomIn.type = 'button';
    zoomIn.className = 'secondary';
    zoomIn.textContent = '+';
    zoomIn.addEventListener('click', () => {
      ds.zoom = Math.min(2.5, Math.round((ds.zoom + 0.1) * 10) / 10);
      render();
    });

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'secondary';
    close.textContent = 'Close';
    close.addEventListener('click', () => {
      ds.open = false;
      ds.doc = null;
      closeModal();
    });

    controls.appendChild(prev);
    controls.appendChild(next);
    controls.appendChild(pageLabel);
    controls.appendChild(zoomOut);
    controls.appendChild(zoomIn);
    controls.appendChild(close);

    header.appendChild(title);
    header.appendChild(controls);

    const body = document.createElement('div');
    body.className = 'modal-body';

    if (!ds.pdfUrl || !ds.pageCount) {
      const empty = document.createElement('div');
      empty.className = 'panel';
      empty.dataset.testid = 'maths-datasheet-empty';
      empty.textContent = 'No datasheet found for this year/paper.';
      body.appendChild(empty);
    } else {
      const view = document.createElement('div');
      view.className = 'ds-view';
      const canvas = document.createElement('canvas');
      canvas.setAttribute('data-role', 'datasheet');
      canvas.dataset.testid = 'maths-datasheet-canvas';
      view.appendChild(canvas);
      body.appendChild(view);
    }

    modal.appendChild(header);
    modal.appendChild(body);
    backdrop.appendChild(modal);

    modalRoot.innerHTML = '';
    modalRoot.appendChild(backdrop);

    // Render asynchronously after the modal is mounted.
    if (ds.pdfUrl && ds.pageCount && ds.doc) {
      queueMicrotask(() => {
        renderDatasheetModalPage(token).catch((error) => {
          console.error('Datasheet render failure', error);
        });
      });
    }
  }

  async function toggleDatasheet(openInNewTab) {
    const year = active.year !== 'all' ? active.year : null;
    const paper = active.paper !== 'all' ? active.paper : null;

    if (openInNewTab) {
      const params = new URLSearchParams();
      if (year) params.set('year', year);
      if (paper) params.set('paper', paper);
      const url = `${BASE_PATH}/datasheet?${params.toString()}`;
      window.open(url, '_blank', 'noopener,noreferrer');
      return;
    }

    if (active.datasheet.open) {
      active.datasheet.open = false;
      active.datasheet.doc = null;
      closeModal();
      return;
    }

    active.datasheet.open = true;
    active.datasheet.title = `Datasheet · ${year || 'All years'} · ${paper ? paperLabel(paper) : 'All papers'}`;
    active.datasheet.zoom = 1;
    active.datasheet.pageIndex = 0;
    active.datasheet.pdfUrl = '';
    active.datasheet.pageCount = 0;
    active.datasheet.fileId = null;
    active.datasheet.doc = null;

    try {
      const params = new URLSearchParams();
      if (year) params.set('year', year);
      if (paper) params.set('paper', paper);
      const data = await apiGet(`/api/maths/datasheet?${params.toString()}`);
      if (!data) return;
      active.datasheet.pdfUrl = String(data.pdfUrl || '');
      active.datasheet.fileId = data.fileId || null;

      if (active.datasheet.pdfUrl) {
        active.datasheet.doc = await loadPdfDocument(active.datasheet.pdfUrl);
        active.datasheet.pageCount = active.datasheet.doc.numPages || 0;
      }
      openDatasheetModal();
    } catch (error) {
      setStatus(error.message || 'Unable to load datasheet.', 'error');
      active.datasheet.pdfUrl = '';
      active.datasheet.pageCount = 0;
      active.datasheet.doc = null;
      openDatasheetModal();
    }
  }

  function findNeighborQuestionId(delta) {
    const id = active.question && active.question.id;
    if (!id) return null;
    const idx = active.questionIndexById.get(id);
    if (idx == null) return null;
    const nextIdx = idx + delta;
    if (nextIdx < 0 || nextIdx >= active.questionIds.length) return null;
    return active.questionIds[nextIdx];
  }

  function handleKeydown(event) {
    if (event.defaultPrevented) return;
    if (isTypingTarget(event.target)) {
      if (event.key === 'Escape' && active.datasheet.open) {
        active.datasheet.open = false;
        active.datasheet.doc = null;
        closeModal();
      }
      return;
    }

    if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      searchInput.focus();
      return;
    }

    if (event.key === 'd' || event.key === 'D') {
      event.preventDefault();
      toggleDatasheet(event.shiftKey);
      return;
    }

    if (event.key === 'a' || event.key === 'A') {
      const path = routePath();
      if (!path.startsWith('/q/')) return;
      event.preventDefault();
      active.showAnswer = !active.showAnswer;
      render();
      return;
    }

    if (event.key === 'r' || event.key === 'R') {
      const path = routePath();
      if (!path.startsWith('/q/') && !path.startsWith('/review/')) return;
      event.preventDefault();
      const id = active.question && active.question.id;
      if (!id) return;
      if (path.startsWith('/review/')) {
        navigate(`/q/${encodeURIComponent(id)}`);
      } else {
        navigate(`/review/${encodeURIComponent(id)}`);
      }
      return;
    }

    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      const path = routePath();
      if (!path.startsWith('/q/') && !path.startsWith('/review/')) return;
      event.preventDefault();
      const neighbor = findNeighborQuestionId(event.key === 'ArrowLeft' ? -1 : 1);
      if (neighbor) {
        const isReview = path.startsWith('/review/');
        navigate(`${isReview ? '/review/' : '/q/'}${encodeURIComponent(neighbor)}`);
      }
    }

    if (event.key === 'Escape' && active.datasheet.open) {
      event.preventDefault();
      active.datasheet.open = false;
      active.datasheet.doc = null;
      closeModal();
    }
  }

  async function loadQuestion(id) {
    const data = await apiGet(`/api/maths/question?id=${encodeURIComponent(id)}`);
    if (!data) return null;
    return data.question || null;
  }

  async function renderRoute() {
    const path = routePath();

    if (path === '/' || path === '') {
      routeEl.innerHTML = '';
      routeEl.appendChild(buildListView());
      return;
    }

    if (path.startsWith('/q/')) {
      const id = decodeURIComponent(path.slice('/q/'.length));
      if (!id) {
        routeEl.textContent = 'Missing question id.';
        return;
      }
      setStatus('Loading question...', '');
      const question = await loadQuestion(id);
      if (!question) {
        setStatus('Question not found.', 'error');
        routeEl.textContent = 'Question not found.';
        return;
      }
      active.question = question;
      setStatus('', '');
      routeEl.innerHTML = '';
      routeEl.appendChild(buildDetailView(question));
      return;
    }

    if (path.startsWith('/review/')) {
      const id = decodeURIComponent(path.slice('/review/'.length));
      if (!id) {
        routeEl.textContent = 'Missing question id.';
        return;
      }
      setStatus('Loading review...', '');
      const question = await loadQuestion(id);
      if (!question) {
        setStatus('Question not found.', 'error');
        routeEl.textContent = 'Question not found.';
        return;
      }
      active.question = question;
      setStatus('', '');
      const filesById = new Map();
      let pastPaperFiles = [];
      let markSchemeFiles = [];
      try {
        const [past, schemes] = await Promise.all([
          apiGet(`/api/maths/files?type=past_paper&year=${encodeURIComponent(question.year)}&paper=${encodeURIComponent(question.paperNumber)}`),
          apiGet(`/api/maths/files?type=mark_scheme&year=${encodeURIComponent(question.year)}&paper=${encodeURIComponent(question.paperNumber)}`),
        ]);
        pastPaperFiles = Array.isArray(past && past.files) ? past.files : [];
        markSchemeFiles = Array.isArray(schemes && schemes.files) ? schemes.files : [];
        [...pastPaperFiles, ...markSchemeFiles].forEach((file) => {
          if (file && file.id) filesById.set(file.id, file);
        });
      } catch (error) {
        console.warn('Unable to preload maths files for review', error);
      }
      routeEl.innerHTML = '';
      routeEl.appendChild(buildReviewView(question, { filesById, pastPaperFiles, markSchemeFiles }));
      return;
    }

    if (path.startsWith('/diagnostics')) {
      setStatus('Loading diagnostics...', '');
      const data = await apiGet('/api/maths/diagnostics');
      if (!data) return;
      setStatus('', '');
      routeEl.innerHTML = '';
      routeEl.appendChild(buildDiagnosticsView(data));
      return;
    }

    if (path.startsWith('/datasheet')) {
      // Allow opening datasheet in a new tab via /maths/datasheet.
      setStatus('Loading datasheet...', '');
      await toggleDatasheet(false);
      setStatus('', '');
      routeEl.innerHTML = '';
      routeEl.appendChild(buildListView());
      return;
    }

    routeEl.textContent = 'Not found.';
  }

  async function render() {
    if (!session.approved) return;

    // Keep the list view in sync for keyboard navigation.
    if (!catalog.questions.length) {
      try {
        await loadQuestions();
      } catch (error) {
        setStatus(error.message || 'Unable to load questions.', 'error');
      }
    }

    try {
      await renderRoute();
    } catch (error) {
      console.error('Render failure', error);
      setStatus(error.message || 'Unable to render page.', 'error');
    }

    if (active.datasheet.open) {
      openDatasheetModal();
    }
  }

  async function init() {
    parseQuery();

    if (!api) {
      setStatus('Auth client failed to load.', 'error');
      return;
    }

    diagnosticsLink.href = `${BASE_PATH}/diagnostics`;

    document.addEventListener('click', onLinkClick);
    window.addEventListener('popstate', () => render());
    window.addEventListener('keydown', handleKeydown);

    yearSelect.addEventListener('change', async () => {
      active.year = yearSelect.value;
      syncQueryToUrl();
      catalog.questions = [];
      await loadQuestions();
      render();
    });

    paperSelect.addEventListener('change', async () => {
      active.paper = paperSelect.value;
      syncQueryToUrl();
      catalog.questions = [];
      await loadQuestions();
      render();
    });

    searchInput.addEventListener('input', async () => {
      active.search = searchInput.value;
      syncQueryToUrl();
      catalog.questions = [];

      // Debounce lightly without timers for simplicity.
      await loadQuestions();
      render();
    });

    datasheetBtn.addEventListener('click', () => {
      toggleDatasheet(false);
    });

    logoutBtn.addEventListener('click', async () => {
      try {
        await api.apiRequest('/api/auth/logout', {
          method: 'POST',
          csrf: true,
          json: {},
        });
      } finally {
        window.location.href = '/login/';
      }
    });

    try {
      const ok = await requireApprovedSession();
      if (!ok) return;

      await loadYears();

      paperSelect.value = active.paper;
      searchInput.value = active.search;

      await loadQuestions();
      syncQueryToUrl();

      setStatus('Ready.', 'ok');
      render();
    } catch (error) {
      console.error('Init failure', error);
      setStatus(error.message || 'Unable to initialize maths question bank.', 'error');
    }
  }

  init();
})();
