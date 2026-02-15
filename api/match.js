const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(process.cwd(), 'public', 'data', 'papers.json');
let cachedData = null;

const RUAE_GUIDANCE = `Reading for Understanding, Analysis and Evaluation (30 marks)\n\nAs the title of the paper suggests, there are three core skills being tested in this exam:\n- your ability to read and understand an unfamiliar piece of non-fiction prose\n- your ability to analyse a range of literary devices used by a writer to create a particular effect\n- your ability to evaluate the success of the writer in employing these techniques\n\nYou will have 1 hour and 30 minutes to complete the RUAE exam. The paper is marked out of 30 and is therefore worth 30% of your overall grade.\n\nThe RUAE passage\nAt Higher you will be faced with two passages in the exam. These passages should be linked by the same topic, although the writers might take very different approaches or attitudes to the topic.\n\nThe majority of questions will deal with passage one; the final question deals with both passages. In this final question you will be asked to look at the main areas of agreement and/or disagreement between the two writers.\n\nOften, reading and understanding the passages is the trickiest bit for candidates. Passages at Higher will be full of demanding vocabulary and complicated lines of thought.\n\nThe questions\nIt is perhaps helpful to think about the three question areas in this paper in the following way:\n- what is the writer saying? (Understanding)\n- how is the writer saying it? (Analysis)\n- how well did the writer say it? (Evaluation)\n\nWorking out whether a question is a U or an A or an E can be tricky. But looking for certain trigger words in each question will help:\n\nUnderstanding questions\n- What are the key points…\n- In your own words…\n- Summarise\n- Explain what…\n\nAnalysis questions\n- With reference to the features of language used by the writer show how…\n- Analyse how techniques used by the writer…\n- How does the word choice/imagery used by the writer…\n- How is tone created…\n\nEvaluative questions\n- How effective is…\n- How well…\n\nOnce you have figured out what type of question you are dealing with, you should then look at the mark allocation. For example:\n- a 4-mark analysis question will require: 2 x Quotation/Technique/Analysis (with link to question)\n- a 5-mark understanding question might be best bullet pointed for clarity.\n\nLanguage features\n- sentence structure (short/minor sentences, parenthesis, lists, punctuation etc.)\n- imagery (metaphors, similes, personification)\n- word choice\n- tone (sarcastic, humorous, ironic, argumentative, bitter, frustrated etc.)\n- linking sentences\n- turning point in argument\n\nThe final question\n- Identify areas of agreement/disagreement\n- Provide supporting quotations/references\n- Comment in detail/insightfully on each piece of evidence\n\nFailure to identify any key areas of agreement/disagreement or a clear misunderstanding of the task results in 0 marks.\n\nStructure ideas: a table, bullet points, headings, or linked statements with detailed reasoning.`;

function loadPapers() {
  if (!cachedData) {
    cachedData = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  }
  return cachedData;
}

function extractOutputText(responseJson) {
  if (responseJson.output_text) return responseJson.output_text;
  if (!Array.isArray(responseJson.output)) return null;
  for (const item of responseJson.output) {
    if (item.type === 'message' && Array.isArray(item.content)) {
      for (const content of item.content) {
        if (content.type === 'output_text') {
          return content.text;
        }
      }
    }
  }
  return null;
}

function buildContext(paper, question) {
  let lines = [];
  if (question.lineRange) {
    const passageId = question.passage === 'passage2' ? 'passage2' : 'passage1';
    const passage = paper.passages.find((item) => item.id === passageId);
    if (passage) {
      const start = question.lineRange.start;
      const end = question.lineRange.end;
      let count = 0;
      for (const text of passage.lines) {
        if (text.trim() !== '') {
          count += 1;
        }
        if (count >= start && count <= end) {
          lines.push({ lineNumber: count, text });
        }
        if (count > end) break;
      }
    }
  } else if (question.passage === 'both') {
    lines = paper.passages.flatMap((passage) =>
      passage.lines.map((text, index) => ({
        lineNumber: index + 1,
        text,
        passage: passage.title,
      }))
    );
  }

  return lines;
}

function extractQuoteTokens(text) {
  const tokens = [];
  if (!text) return tokens;
  const doubleMatches = text.match(/\"([^\"]+)\"/g) || [];
  const singleMatches = text.match(/'([^']+)'/g) || [];
  for (const match of doubleMatches) tokens.push(match.replace(/\"/g, ''));
  for (const match of singleMatches) tokens.push(match.replace(/'/g, ''));
  const parenMatches = text.match(/\(([^)]+)\)/g) || [];
  for (const match of parenMatches) {
    const content = match.replace(/[()]/g, '').trim();
    const cleaned = content.replace(/["',.\s]+/g, '');
    if (cleaned) tokens.push(content);
  }
  return tokens.map((token) => token.trim()).filter(Boolean);
}

function normalize(value) {
  return value.toLowerCase().replace(/\s+/g, ' ').trim();
}

function isQuoteInMarkScheme(quote, markScheme) {
  if (!quote) return false;
  const quoteNorm = normalize(quote);
  if (!quoteNorm) return false;

  for (const item of markScheme) {
    const tokens = extractQuoteTokens(item);
    if (!tokens.length) {
      const itemNorm = normalize(item);
      if (itemNorm.includes(quoteNorm) || quoteNorm.includes(itemNorm)) {
        return true;
      }
      continue;
    }
    for (const token of tokens) {
      const tokenNorm = normalize(token);
      if (tokenNorm.length < 3) continue;
      if (quoteNorm.includes(tokenNorm) || tokenNorm.includes(quoteNorm)) {
        return true;
      }
    }
  }
  return false;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed.' });
    return;
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'OPENAI_API_KEY is not set on the server.' });
    return;
  }

  let payload = req.body;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch (error) {
      res.status(400).json({ error: 'Invalid JSON body.' });
      return;
    }
  }

  const { paperId, questionNumber, answer, mode } = payload || {};
  const data = loadPapers();
  const paper = data.papers.find((item) => item.id === paperId);
  if (!paper) {
    res.status(404).json({ error: 'Paper not found.' });
    return;
  }

  const question = paper.questions.find((item) => item.number === Number(questionNumber));
  if (!question) {
    res.status(404).json({ error: 'Question not found.' });
    return;
  }

  const lines = buildContext(paper, question);
  const markScheme = question.markScheme || [];

  const isMarkMode = mode === 'mark';

  const instructions = isMarkMode
    ? [
        'You are grading a Higher English RUAE answer.',
        'Use the question, passage lines, mark scheme bullets, and the RUAE guidance provided.',
        'Return a score out of the maximum marks for the question.',
        'Explain clearly why marks were awarded or not awarded.',
        'Return JSON only, matching the provided schema.',
      ].join(' ')
    : [
        'You are helping a student locate the exact quotation they used from the passage lines provided.',
        'Only use the supplied lines.',
        'If the student did not use a direct quote from the lines, return quote=null and lineNumber=null.',
        'If multiple quotes appear, pick the clearest, shortest quote that appears verbatim in the lines.',
        'Return JSON only, matching the provided schema.',
      ].join(' ');

  const userInput = isMarkMode
    ? {
        question: question.text,
        answer: answer || '',
        lines,
        markScheme,
        maxMarks: question.marks || 0,
        guidance: RUAE_GUIDANCE,
      }
    : {
        question: question.text,
        answer: answer || '',
        lines,
      };

  const responseFormat = isMarkMode
    ? {
        type: 'json_schema',
        name: 'mark_answer',
        strict: true,
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            score: { type: 'integer' },
            max: { type: 'integer' },
            reasoning: { type: 'string' },
          },
          required: ['score', 'max', 'reasoning'],
        },
      }
    : {
        type: 'json_schema',
        name: 'quote_match',
        strict: true,
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            quote: { type: ['string', 'null'] },
            lineNumber: { type: ['integer', 'null'] },
          },
          required: ['quote', 'lineNumber'],
        },
      };

  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';

  try {
    const apiResponse = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        instructions,
        input: JSON.stringify(userInput),
        temperature: 0.2,
        text: { format: responseFormat },
      }),
    });

    const responseJson = await apiResponse.json();
    if (!apiResponse.ok) {
      res.status(apiResponse.status).json({
        error: responseJson.error?.message || 'OpenAI API request failed.',
      });
      return;
    }

    const outputText = extractOutputText(responseJson);
    if (!outputText) {
      res.status(500).json({ error: 'OpenAI response did not include output text.' });
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(outputText);
    } catch (error) {
      res.status(500).json({ error: 'Failed to parse JSON from OpenAI response.' });
      return;
    }

    if (!isMarkMode) {
      const inMarkScheme = parsed.quote ? isQuoteInMarkScheme(parsed.quote, markScheme) : false;
      res.status(200).json({
        quote: parsed.quote,
        lineNumber: parsed.lineNumber,
        inMarkScheme,
      });
      return;
    }

    res.status(200).json(parsed);
  } catch (error) {
    res.status(500).json({ error: 'Unable to reach OpenAI API.' });
  }
};
