import { expect, test } from 'vitest'
import { formatBytes, formatMs, passwordIssues, prettyFp, shortFp } from './format'

test('formatBytes', () => {
  expect(formatBytes(512)).toBe('512 B')
  expect(formatBytes(1536)).toBe('1.50 KB')
  expect(formatBytes(5 * 1024 * 1024)).toBe('5.00 MB')
})

test('formatMs', () => {
  expect(formatMs(0.123)).toBe('0.12 ms')
  expect(formatMs(2500)).toBe('2.50 s')
})

test('fingerprints', () => {
  const fp = 'a'.repeat(64)
  expect(shortFp(fp)).toBe('aaaaaaaa…aaaaaa')
  expect(prettyFp(fp)).toBe('aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa')
})

test('passwordIssues', () => {
  expect(passwordIssues('Str0ng-Passw0rd!')).toEqual([])
  expect(passwordIssues('short')).toContain('At least 10 characters')
})
