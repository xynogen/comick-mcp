import assert from 'node:assert/strict';
import { ChildProcess, type ExecFileException, type ExecFileOptions } from 'node:child_process';
import { PassThrough } from 'node:stream';
import type { Server } from 'node:http';
import { z } from 'zod';

export type ExecStub = (command: string, args: readonly string[], options: ExecFileOptions,
  done: (error: ExecFileException | null, stdout: string, stderr: string) => void) => ChildProcess;

export function inputProcess(receive: (input: string) => void): ChildProcess {
  const child = new ChildProcess();
  child.stdin = new PassThrough();
  let input = '';
  child.stdin.on('data', (chunk: Buffer) => { input += chunk.toString('utf8'); });
  child.stdin.on('finish', () => receive(input));
  return child;
}

export function port(server: Server): number {
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return address.port;
}

export function required<T>(value: T | null | undefined): T {
  assert.ok(value !== undefined && value !== null);
  return value;
}

export const credentialSchema = z.object({
  access_token: z.string(), refresh_token: z.string().optional(), token_type: z.string(),
  scope: z.string(), client_id: z.string(), expires_at: z.number(),
});
export const keyringInput = z.object({ operation: z.string(), target: z.string(), secret: z.string().optional() });
export const writeBody = z.object({
  status: z.number().optional(), rating: z.number().nullable().optional(),
  progress: z.object({ hid: z.string().optional(), number: z.string().optional(), volume: z.string().nullable().optional() }).nullable().optional(),
});
export const requestLog = z.object({
  path: z.string(), query: z.array(z.tuple([z.string(), z.string()])), method: z.string(), body: z.unknown(),
});
export const failureSchema = z.object({ error: z.object({
  code: z.string(), recommendation: z.string().optional(), retryable: z.boolean().optional(), retry_after: z.string().optional(), status: z.number().optional(),
  issues: z.array(z.object({
    path: z.array(z.union([z.string(), z.number()])), code: z.string(), recommendation: z.string(),
    expected: z.object({ maximum: z.number().optional() }).passthrough().optional(),
  })).optional(),
}) });

export function textContent(response: { content: readonly { type: string; text?: string }[] }): string {
  const content = response.content[0];
  assert.ok(content?.type === 'text');
  return required(content.text);
}
