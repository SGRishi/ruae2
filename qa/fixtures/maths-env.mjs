import { createMemoryStore, createMathsMemoryStore } from '../../worker.js';
import { createMemoryAssets } from './memory-assets.mjs';

function bytesToBase64(bytes) {
  let output = '';
  for (let i = 0; i < bytes.length; i += 1) {
    output += String.fromCharCode(bytes[i]);
  }
  return btoa(output);
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256Base64Url(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToBase64Url(new Uint8Array(digest));
}

export const QA_SECRETS = {
  SESSION_SECRET: 'test-session-secret',
  PASSWORD_PEPPER: 'test-pepper',
};

export const QA_SESSIONS = {
  approved: {
    token: 'test_approved_session_1234567890abcd',
    username: 'approveduser',
    status: 'approved',
  },
  pending: {
    token: 'test_pending_session_1234567890abcd',
    username: 'pendinguser',
    status: 'pending',
  },
};

const PNG_1X1_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/lGv9owAAAABJRU5ErkJggg==';

function pngBytes() {
  return Uint8Array.from(Buffer.from(PNG_1X1_BASE64, 'base64'));
}

export function qaBaseUrl(port = 8789) {
  return `http://127.0.0.1:${Number(port)}`;
}

export async function createQaEnv(origin) {
  const nowSeconds = Math.floor(Date.now() / 1000);

  const authStore = createMemoryStore({
    users: [
      {
        id: 1,
        email: QA_SESSIONS.approved.username,
        pass_salt: 'salt',
        pass_hash: 'hash',
        status: 'approved',
      },
      {
        id: 2,
        email: QA_SESSIONS.pending.username,
        pass_salt: 'salt',
        pass_hash: 'hash',
        status: 'pending',
      },
    ],
  });

  const approvedHash = await sha256Base64Url(`${QA_SECRETS.SESSION_SECRET}\u0000${QA_SESSIONS.approved.token}`);
  const pendingHash = await sha256Base64Url(`${QA_SECRETS.SESSION_SECRET}\u0000${QA_SESSIONS.pending.token}`);

  await authStore.createSession({
    id: 'sess_approved',
    userId: 1,
    tokenHash: approvedHash,
    createdAt: nowSeconds,
    expiresAt: nowSeconds + 3600,
    lastSeenAt: nowSeconds,
    ipAddress: '127.0.0.1',
    userAgent: 'qa',
  });

  await authStore.createSession({
    id: 'sess_pending',
    userId: 2,
    tokenHash: pendingHash,
    createdAt: nowSeconds,
    expiresAt: nowSeconds + 3600,
    lastSeenAt: nowSeconds,
    ipAddress: '127.0.0.1',
    userAgent: 'qa',
  });

  const maths = {
    files: [
      { id: 'paper_2023_1', path: 'paper_2023_1.pdf', type: 'past_paper', year: 2023, paperNumber: 1, pageCount: 2 },
      { id: 'ms_2023_1', path: 'ms_2023_1.pdf', type: 'mark_scheme', year: 2023, paperNumber: 1, pageCount: 2 },
      { id: 'paper_2023_2', path: 'paper_2023_2.pdf', type: 'past_paper', year: 2023, paperNumber: 2, pageCount: 2 },
      { id: 'ms_2023_2', path: 'ms_2023_2.pdf', type: 'mark_scheme', year: 2023, paperNumber: 2, pageCount: 2 },
      { id: 'paper_2024_1', path: 'paper_2024_1.pdf', type: 'past_paper', year: 2024, paperNumber: 1, pageCount: 2 },
      { id: 'ms_2024_1', path: 'ms_2024_1.pdf', type: 'mark_scheme', year: 2024, paperNumber: 1, pageCount: 2 },
    ],
    questions: [
      { id: 'q_2024_1_1', year: 2024, paperNumber: 1, qNumber: 1, qLabel: 'Question 1', topic: 'geometry', textExtracted: 'Triangles' },
      { id: 'q_2023_2_1', year: 2023, paperNumber: 2, qNumber: 1, qLabel: 'Question 1', topic: 'algebra', textExtracted: 'Solve for x' },
      { id: 'q_2023_2_2', year: 2023, paperNumber: 2, qNumber: 2, qLabel: 'Question 2', topic: 'functions', textExtracted: '(a) Evaluate f(2). (b) Solve f(x)=0.' },
      { id: 'q_2023_1_1', year: 2023, paperNumber: 1, qNumber: 1, qLabel: 'Question 1', topic: 'calculus', textExtracted: 'Differentiate' },
    ],
    crops: [
      // 2024 Paper 1
      {
        id: 'crop_q_2024_1_1_thumb',
        questionId: 'q_2024_1_1',
        kind: 'thumb',
        fileId: 'paper_2024_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2024/1/q_2024_1_1/thumb.png',
      },
      {
        id: 'crop_q_2024_1_1_question_01',
        questionId: 'q_2024_1_1',
        kind: 'question',
        fileId: 'paper_2024_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 300,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2024/1/q_2024_1_1/q_01.png',
      },
      {
        id: 'crop_q_2024_1_1_answer_01',
        questionId: 'q_2024_1_1',
        kind: 'answer',
        fileId: 'ms_2024_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 300,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2024/1/q_2024_1_1/a_01.png',
      },

      // 2023 Paper 2 Q1
      {
        id: 'crop_q_2023_2_1_thumb',
        questionId: 'q_2023_2_1',
        kind: 'thumb',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_1/thumb.png',
      },
      {
        id: 'crop_q_2023_2_1_question_01',
        questionId: 'q_2023_2_1',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 300,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_1/q_01.png',
      },
      {
        id: 'crop_q_2023_2_1_answer_01',
        questionId: 'q_2023_2_1',
        kind: 'answer',
        fileId: 'ms_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 300,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_1/a_01.png',
      },

      // 2023 Paper 2 Q2 (multi-part)
      {
        id: 'crop_q_2023_2_2_thumb',
        questionId: 'q_2023_2_2',
        kind: 'thumb',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/thumb.png',
      },
      {
        id: 'crop_q_2023_2_2_question_01',
        questionId: 'q_2023_2_2',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/q_01.png',
      },
      {
        id: 'crop_q_2023_2_2_question_02',
        questionId: 'q_2023_2_2',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 1,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/q_02.png',
      },
      {
        id: 'crop_q_2023_2_2_answer_01',
        questionId: 'q_2023_2_2',
        kind: 'answer',
        fileId: 'ms_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/a_01.png',
      },
      {
        id: 'crop_q_2023_2_2_answer_02',
        questionId: 'q_2023_2_2',
        kind: 'answer',
        fileId: 'ms_2023_2',
        pageIndex: 1,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/a_02.png',
      },

      // 2023 Paper 1
      {
        id: 'crop_q_2023_1_1_thumb',
        questionId: 'q_2023_1_1',
        kind: 'thumb',
        fileId: 'paper_2023_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/1/q_2023_1_1/thumb.png',
      },
      {
        id: 'crop_q_2023_1_1_question_01',
        questionId: 'q_2023_1_1',
        kind: 'question',
        fileId: 'paper_2023_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/1/q_2023_1_1/q_01.png',
      },
      {
        id: 'crop_q_2023_1_1_answer_01',
        questionId: 'q_2023_1_1',
        kind: 'answer',
        fileId: 'ms_2023_1',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 300,
        y1: 240,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/1/q_2023_1_1/a_01.png',
      },
    ],
  };

  const mathsStore = createMathsMemoryStore(maths);
  const assets = createMemoryAssets();

  const png = pngBytes();
  for (const crop of maths.crops) {
    if (!crop.storageKey) continue;
    await assets.put(crop.storageKey, png, { metadata: { contentType: 'image/png' } });
  }

  const env = {
    ...QA_SECRETS,
    ALLOWED_ORIGINS: origin ? `${origin},https://rishisubjects.co.uk` : 'https://rishisubjects.co.uk',
    REQUIRE_MANUAL_APPROVAL: 'false',
    ALLOW_TEST_AUTH: 'true',
    OPENAI_API_KEY: 'qa-openai-test-key',
    OPENAI_MODEL: 'gpt-4o-mini',
    AUTH_STORE: authStore,
    MATHS_STORE: mathsStore,
    MATHS_ASSETS: assets,
  };

  const fixtures = {
    origin,
    sessions: QA_SESSIONS,
    maths: {
      questionIds: maths.questions.map((q) => q.id),
    },
  };

  return { env, fixtures };
}
