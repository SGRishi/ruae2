const yearSelect = document.getElementById('yearSelect');
const paperSelect = document.getElementById('paperSelect');
const viewSelect = document.getElementById('viewSelect');
const questionSelect = document.getElementById('questionSelect');
const questionSelectWrap = document.getElementById('questionSelectWrap');
const schemeView = document.getElementById('schemeView');
const aiModeSelect = document.getElementById('aiMode');
const questionsEl = document.getElementById('questions');
const logoutBtn = document.getElementById('logoutBtn');
const sessionUsernameEl = document.getElementById('sessionEmail');

const LOGIN_PATH = '/login/?next=%2Fruae%2F';
const api = window.RuaeApi;

let papers = [];
let activePaper = null;
let viewMode = 'all';
let activeQuestionNumber = null;
let schemeMode = 'table';
let aiMode = 'quote';

function formatLines(lines) {
  return lines.join('\n');
}

function passageById(paper, id) {
  return paper.passages.find((passage) => passage.id === id);
}

function getLinesForQuestion(paper, question) {
  if (!question.lineRange) return [];
  const passageId = question.passage === 'passage2' ? 'passage2' : 'passage1';
  const passage = passageById(paper, passageId);
  if (!passage) return [];
  const start = question.lineRange.start;
  const end = question.lineRange.end;
  const output = [];
  let lineCount = 0;
  for (const line of passage.lines) {
    if (line.trim() !== '') {
      lineCount += 1;
    }
    if (lineCount >= start && lineCount <= end) {
      output.push(line);
    }
    if (lineCount > end) break;
  }
  return output;
}

function populateYearSelect() {
  const years = Array.from(new Set(papers.map((paper) => paper.year).filter(Boolean))).sort(
    (a, b) => a - b
  );
  yearSelect.innerHTML = '';

  if (!years.length) {
    yearSelect.style.display = 'none';
    return;
  }

  years.forEach((year) => {
    const option = document.createElement('option');
    option.value = String(year);
    option.textContent = String(year);
    yearSelect.appendChild(option);
  });
}

function populatePaperSelect(year) {
  const filtered = papers.filter((paper) => (year ? paper.year === year : true));
  paperSelect.innerHTML = '';

  filtered.forEach((paper) => {
    const option = document.createElement('option');
    option.value = paper.id;
    option.textContent = paper.label;
    paperSelect.appendChild(option);
  });

  if (filtered.length) {
    renderPaper(filtered[0]);
  } else {
    questionsEl.innerHTML = '';
  }
}

function populateQuestionSelect(paper) {
  questionSelect.innerHTML = '';
  if (!paper) return;
  paper.questions.forEach((question) => {
    const option = document.createElement('option');
    option.value = String(question.number);
    option.textContent = `Question ${question.number}`;
    questionSelect.appendChild(option);
  });
  activeQuestionNumber = paper.questions[0]?.number ?? null;
  if (activeQuestionNumber !== null) {
    questionSelect.value = String(activeQuestionNumber);
  }
}

function getVisibleQuestions(paper) {
  if (!paper) return [];
  if (viewMode === 'single') {
    const target = paper.questions.find((q) => q.number === Number(activeQuestionNumber));
    return target ? [target] : [];
  }
  return paper.questions;
}

function splitQuoteAnalysis(text) {
  const quoteParts = [];
  let analysis = text;

  const pushQuotePart = (value) => {
    if (!value) return;
    const cleaned = value.replace(/["']/g, '').replace(/[()\s.,;:]+/g, '').trim();
    if (!cleaned) return;
    quoteParts.push(value);
  };

  analysis = analysis.replace(/\"([^\"]+)\"/g, (_match, content) => {
    pushQuotePart(`\"${content}\"`);
    return '';
  });

  analysis = analysis.replace(/(^|[^\w])'([^']+)'/g, (_match, prefix, content) => {
    pushQuotePart(`'${content}'`);
    return prefix || ' ';
  });

  analysis = analysis.replace(/\(([^)]+)\)/g, (_match, content) => {
    pushQuotePart(`(${content})`);
    return '';
  });

  analysis = analysis
    .replace(/(^|\s)[/|](?=\s|$)/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .replace(/\s+,/g, ',')
    .replace(/\s+\./g, '.')
    .trim();

  if (!analysis) analysis = text.trim();

  const uniqueQuotes = Array.from(new Set(quoteParts));

  return {
    quote: uniqueQuotes.join(' | '),
    analysis,
  };
}

function buildSchemeList(items) {
  const list = document.createElement('ul');
  list.className = 'mark-scheme';
  items.forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    list.appendChild(li);
  });
  return list;
}

function buildSchemeTable(items) {
  const table = document.createElement('div');
  table.className = 'scheme-table';

  const header = document.createElement('div');
  header.className = 'scheme-row scheme-header';
  const hQuote = document.createElement('div');
  hQuote.textContent = 'Quote';
  const hAnalysis = document.createElement('div');
  hAnalysis.textContent = 'Analysis';
  header.appendChild(hQuote);
  header.appendChild(hAnalysis);
  table.appendChild(header);

  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'scheme-row';
    const { quote, analysis } = splitQuoteAnalysis(item);
    const quoteCell = document.createElement('div');
    quoteCell.className = 'scheme-cell scheme-quote';
    quoteCell.textContent = quote || '—';
    const analysisCell = document.createElement('div');
    analysisCell.className = 'scheme-cell scheme-analysis';
    analysisCell.textContent = analysis;
    row.appendChild(quoteCell);
    row.appendChild(analysisCell);
    table.appendChild(row);
  });

  return table;
}

async function checkAnswer(question, answer, outputEl) {
  if (!answer.trim()) {
    outputEl.textContent = 'Add a short quote to check against the mark scheme.';
    return;
  }

  outputEl.textContent = aiMode === 'mark' ? 'Marking answer...' : 'Checking quote...';

  try {
    const { response, data } = await api.apiRequest('/api/match', {
      method: 'POST',
      csrf: true,
      json: {
        paperId: activePaper.id,
        questionNumber: question.number,
        answer,
        mode: aiMode,
      },
    });

    if (response.status === 401 || response.status === 403) {
      window.location.href = LOGIN_PATH;
      return;
    }

    if (!response.ok) {
      outputEl.textContent = data.error || 'Something went wrong with the AI request.';
      return;
    }

    if (aiMode === 'mark') {
      if (data.score == null) {
        outputEl.textContent = 'No score returned.';
        return;
      }
      outputEl.textContent = `Score: ${data.score} / ${data.max}. ${data.reasoning}`;
      return;
    }

    if (!data.quote) {
      outputEl.textContent = 'No direct quote detected.';
      return;
    }

    const verdict = data.inMarkScheme ? 'is in the marking scheme' : 'is NOT in the marking scheme';
    outputEl.textContent = `The quote ${data.quote} (line ${data.lineNumber}) ${verdict}.`;
  } catch {
    outputEl.textContent = 'Unable to reach the AI right now.';
  }
}

function renderQuestions(paper) {
  questionsEl.innerHTML = '';

  const questions = getVisibleQuestions(paper);

  questions.forEach((question) => {
    const section = document.createElement('section');
    section.className = 'question';

    const text = document.createElement('div');
    text.className = 'question-text';
    text.textContent = question.text;
    section.appendChild(text);

    if (question.lineRange) {
      const linesBlock = document.createElement('pre');
      linesBlock.className = 'lines-block';
      linesBlock.textContent = formatLines(getLinesForQuestion(paper, question));
      section.appendChild(linesBlock);
    } else if (question.passage === 'both') {
      paper.passages.forEach((passage) => {
        const title = document.createElement('div');
        title.className = 'passage-title';
        title.textContent = passage.title;
        const linesBlock = document.createElement('pre');
        linesBlock.className = 'lines-block';
        linesBlock.textContent = formatLines(passage.lines);
        section.appendChild(title);
        section.appendChild(linesBlock);
      });
    }

    const textarea = document.createElement('textarea');
    textarea.placeholder = 'Write your answer here...';
    section.appendChild(textarea);

    const toggleButton = document.createElement('button');
    toggleButton.textContent = 'Check answer';
    section.appendChild(toggleButton);

    const schemeWrapper = document.createElement('div');
    schemeWrapper.className = 'scheme hidden';

    const aiResult = document.createElement('div');
    aiResult.className = 'ai-result';
    aiResult.textContent =
      aiMode === 'mark'
        ? 'AI marking feedback will appear here.'
        : 'Quote check will appear here.';
    schemeWrapper.appendChild(aiResult);

    if (question.markScheme?.length) {
      const schemeItems = question.markScheme;
      if (schemeMode === 'table') {
        schemeWrapper.appendChild(buildSchemeTable(schemeItems));
      } else {
        schemeWrapper.appendChild(buildSchemeList(schemeItems));
      }
    } else {
      schemeWrapper.appendChild(buildSchemeList(['No mark scheme items found for this question.']));
    }

    section.appendChild(schemeWrapper);

    toggleButton.addEventListener('click', () => {
      const isHidden = schemeWrapper.classList.contains('hidden');
      if (isHidden) {
        schemeWrapper.classList.remove('hidden');
        toggleButton.textContent = 'Hide answers';
        checkAnswer(question, textarea.value, aiResult);
      } else {
        schemeWrapper.classList.add('hidden');
        toggleButton.textContent = 'Check answer';
      }
    });

    questionsEl.appendChild(section);
  });
}

function renderPaper(paper) {
  activePaper = paper;
  populateQuestionSelect(paper);
  renderQuestions(paper);
}

async function requireAuthenticatedUser() {
  const { response, data } = await api.apiRequest('/api/auth/me');

  if (!response.ok || !data.authenticated) {
    window.location.href = LOGIN_PATH;
    return false;
  }

  if (!data.approved) {
    questionsEl.textContent = 'Your account is pending approval.';
    return false;
  }

  if (data.user && (data.user.username || data.user.email)) {
    sessionUsernameEl.textContent = data.user.username || data.user.email;
  }

  return true;
}

async function init() {
  if (!api) {
    questionsEl.textContent = 'Auth client failed to initialize.';
    return;
  }

  const ok = await requireAuthenticatedUser();
  if (!ok) return;

  try {
    const response = await fetch('/data/papers.json', { credentials: 'same-origin' });

    if (!response.ok) {
      throw new Error('Failed to load paper data.');
    }

    const data = await response.json();
    papers = data.papers || [];

    populateYearSelect();
    const initialYear = yearSelect.options.length ? Number(yearSelect.value) : null;
    populatePaperSelect(initialYear);

    yearSelect.addEventListener('change', () => {
      const year = Number(yearSelect.value);
      populatePaperSelect(year);
    });

    paperSelect.addEventListener('change', () => {
      const nextPaper = papers.find((paper) => paper.id === paperSelect.value);
      if (nextPaper) {
        renderPaper(nextPaper);
      }
    });

    viewSelect.addEventListener('change', () => {
      viewMode = viewSelect.value;
      if (viewMode === 'single') {
        questionSelectWrap.classList.remove('hidden');
      } else {
        questionSelectWrap.classList.add('hidden');
      }
      renderQuestions(activePaper);
    });

    questionSelect.addEventListener('change', () => {
      activeQuestionNumber = Number(questionSelect.value);
      renderQuestions(activePaper);
    });

    schemeView.addEventListener('change', () => {
      schemeMode = schemeView.value;
      renderQuestions(activePaper);
    });

    aiModeSelect.addEventListener('change', () => {
      aiMode = aiModeSelect.value;
      renderQuestions(activePaper);
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

    questionSelectWrap.classList.add('hidden');
  } catch {
    questionsEl.textContent = 'Unable to load RUAE data right now.';
  }
}

init();
