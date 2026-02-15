import test from 'node:test';
import assert from 'node:assert/strict';
import { createMathsMemoryStore } from '../../worker.js';

test('multi-part question crops are kept together under one question id', async () => {
  const store = createMathsMemoryStore({
    questions: [
      {
        id: 'q_2023_2_2',
        year: 2023,
        paperNumber: 2,
        qNumber: 2,
        qLabel: 'Question 2',
        topic: 'functions',
        textExtracted: '(a) ... (b) ...',
      },
    ],
    crops: [
      {
        id: 'crop_q_2023_2_2_question_01',
        questionId: 'q_2023_2_2',
        kind: 'question',
        fileId: 'paper_2023_2',
        pageIndex: 0,
        x0: 0,
        y0: 0,
        x1: 100,
        y1: 100,
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
        x1: 100,
        y1: 100,
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
        x1: 100,
        y1: 100,
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
        x1: 100,
        y1: 100,
        renderDpi: 144,
        storageKind: 'r2',
        storageKey: 'maths/crops/2023/2/q_2023_2_2/a_02.png',
      },
    ],
  });

  const list = await store.listQuestions({ year: 2023, paperNumber: 2 });
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'q_2023_2_2');

  const q = await store.getQuestionById('q_2023_2_2');
  assert.ok(q);
  assert.equal(q.id, 'q_2023_2_2');
  assert.equal(q.questionCrops.length, 2);
  assert.equal(q.answerCrops.length, 2);
  assert.equal(q.questionCrops[0].pageIndex, 0);
  assert.equal(q.questionCrops[1].pageIndex, 1);
});
