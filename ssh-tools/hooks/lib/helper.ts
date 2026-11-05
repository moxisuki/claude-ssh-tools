import type { EngineInterface } from 'claude-code'

import type { HelperResult } from './types'

let cachedNode: string | null | undefined

export function helperPath($: EngineInterface): string {
  return `${$.plugin.root.replace(/\\/g, '/')}/helper/ssh-helper.cjs`
}

export async function resolveNode(
  $: EngineInterface,
  configured?: unknown,
): Promise<string | null> {
  if (cachedNode !== undefined) return cachedNode

  const candidates: string[] = []
  if (typeof configured === 'string' && configured.trim()) candidates.push(configured.trim())
  candidates.push('node')

  for (const bin of candidates) {
    const probe = await $.process
      .run([bin, '--version'], { timeoutMs: 5_000 })
      .catch(() => null)
    if (probe && probe.exitCode === 0) {
      cachedNode = bin
      return bin
    }
  }

  cachedNode = null
  return null
}

export async function requireNode(
  $: EngineInterface,
  configured?: unknown,
): Promise<string> {
  const node = await resolveNode($, configured)
  if (node) return node
  throw Object.assign(
    new Error(
      'node was not found on PATH. ssh-tools runs its helper with Node 18+. ' +
        'Install Node, or set nodeBin in the plugin config.',
    ),
    { code: 'backend-missing' },
  )
}

function parseResult(stdout: string, stderr: string, exitCode: number): HelperResult {
  const lines = stdout.trim().split(/\r?\n/).filter(Boolean)
  const last = lines[lines.length - 1]
  if (last) {
    try {
      return JSON.parse(last) as HelperResult
    } catch {
      // fall through to the exit-code path
    }
  }
  return {
    ok: false,
    code: 'backend-missing',
    message:
      (stderr.trim() || stdout.trim() || `helper exited with code ${exitCode}`).slice(0, 4000),
  }
}

export async function runHelper(
  $: EngineInterface,
  node: string,
  op: string,
  request: unknown,
  timeoutMs = 60_000,
): Promise<HelperResult> {
  const result = await $.process
    .run([node, helperPath($), op], {
      stdin: JSON.stringify(request),
      timeoutMs: Math.min(timeoutMs, 600_000),
    })
    .catch(error => {
      const message = error instanceof Error ? error.message : String(error)
      return {
        exitCode: 1,
        stdout: '',
        stderr: `timeout` === message ? message : `${message}`,
      }
    })

  return parseResult(result.stdout, result.stderr, result.exitCode)
}

export function spawnHelper(
  $: EngineInterface,
  node: string,
  op: string,
  request: unknown,
) {
  return $.process.spawn({
    argv: [node, helperPath($), op],
    input: JSON.stringify(request),
  })
}


export interface ProgressLine {
  op?: string
  file?: string
  transferred?: number
  total?: number
}

export async function runHelperStreaming(
  $: EngineInterface,
  node: string,
  op: string,
  request: unknown,
  onProgress: (line: ProgressLine) => void,
): Promise<HelperResult> {
  const stream = spawnHelper($, node, op, request)
  let buffer = ''
  let stderr = ''
  let result: HelperResult | null = null

  try {
    for await (const chunk of stream) {
      if (chunk.stream === 'stderr') {
        stderr += chunk.text
        continue
      }
      buffer += chunk.text
      let index = buffer.indexOf('\n')
      while (index >= 0) {
        const line = buffer.slice(0, index).trim()
        buffer = buffer.slice(index + 1)
        index = buffer.indexOf('\n')
        if (!line) continue
        try {
          const parsed = JSON.parse(line) as Record<string, unknown>
          if (parsed.progress === true) onProgress(parsed as ProgressLine)
          else result = parsed as HelperResult
        } catch {
          // a partial or non-JSON line: ignored
        }
      }
    }
  } catch (error) {
    return {
      ok: false,
      code: 'network',
      message: error instanceof Error ? error.message : String(error),
    }
  }

  if (result) return result
  return {
    ok: false,
    code: 'backend-missing',
    message: stderr.trim() || 'the helper produced no result',
  }
}
