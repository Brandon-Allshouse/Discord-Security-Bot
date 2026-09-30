import { describe, expect, it } from 'vitest';
import { createLimits } from './context.js';

describe('createLimits', () => {
  it('allows each user 10 commands or button clicks a minute, independently', () => {
    const limits = createLimits();
    for (let i = 0; i < 10; i++) expect(limits.interactions.take('user-a')).toBe(true);
    expect(limits.interactions.take('user-a')).toBe(false);
    expect(limits.interactions.take('user-b')).toBe(true);
  });

  it('gives every shard its own limiter', () => {
    const first = createLimits();
    for (let i = 0; i < 10; i++) first.interactions.take('user-a');
    expect(createLimits().interactions.take('user-a')).toBe(true);
  });
});
