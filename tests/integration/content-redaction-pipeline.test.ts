import { describe, it, expect, beforeEach, afterEach, mock } from 'bun:test';

import {
  ingestObservation,
  setIngestContext,
} from '../../src/services/worker/http/shared.js';
import { buildObservationPrompt } from '../../src/sdk/prompts.js';
import {
  redactContent,
  redactionToken,
} from '../../src/shared/content-redaction.js';

const SECRET_KEY = 'sk-test12345678901234567890123456789012';

describe('content redaction pipeline integration', () => {
  let queuedObservation: {
    tool_name: string;
    tool_input: string;
    tool_response: string;
  } | undefined;

  const mockSessionManager = {
    queueObservation: mock(async (_sessionDbId: number, data: typeof queuedObservation) => {
      queuedObservation = data;
    }),
  };

  const mockSessionStore = {
    createSDKSession: mock(() => 42),
    getPromptNumberFromUserPrompts: mock(() => 1),
    getUserPrompt: mock(() => 'implement feature X'),
  };

  const mockDbManager = {
    getSessionStore: mock(() => mockSessionStore),
  };

  const mockEventBroadcaster = {
    broadcastObservationQueued: mock(() => {}),
  };

  beforeEach(() => {
    queuedObservation = undefined;
    mockSessionManager.queueObservation.mockClear();
    mockSessionStore.createSDKSession.mockClear();
    mockSessionStore.getPromptNumberFromUserPrompts.mockClear();
    mockSessionStore.getUserPrompt.mockClear();
    mockDbManager.getSessionStore.mockClear();
    mockEventBroadcaster.broadcastObservationQueued.mockClear();

    setIngestContext({
      sessionManager: mockSessionManager as never,
      dbManager: mockDbManager as never,
      eventBroadcaster: mockEventBroadcaster as never,
    });
  });

  afterEach(() => {
    mock.restore();
  });

  it('ingestObservation redacts secrets in tool output', async () => {
    const result = await ingestObservation({
      contentSessionId: 'content-session-1',
      toolName: 'Bash',
      toolInput: { command: 'curl https://api.example.com' },
      toolResponse: { output: `export OPENAI_API_KEY=${SECRET_KEY}` },
      cwd: '/tmp/test-project',
    });

    expect(result.ok).toBe(true);
    expect(queuedObservation).toBeDefined();
    expect(queuedObservation!.tool_response).not.toContain(SECRET_KEY);
    expect(queuedObservation!.tool_response).toContain(redactionToken('api_key'));
  });

  it('buildObservationPrompt does not include raw API keys', () => {
    const prompt = buildObservationPrompt({
      id: 1,
      tool_name: 'Bash',
      tool_input: JSON.stringify({ command: 'echo key' }),
      tool_output: JSON.stringify({ output: SECRET_KEY }),
      created_at_epoch: Date.now(),
      cwd: '/tmp/test-project',
    });

    expect(prompt).not.toContain(SECRET_KEY);
    expect(prompt).toContain(redactionToken('api_key'));
  });

  it('redactContent with standard mode masks sk- keys', () => {
    const output = redactContent(`api key ${SECRET_KEY}`, { mode: 'standard' });

    expect(output).not.toContain(SECRET_KEY);
    expect(output).toContain(redactionToken('api_key'));
  });
});