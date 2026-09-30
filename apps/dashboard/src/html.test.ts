import { describe, expect, it } from 'vitest';
import { canManage } from './discord-oauth.js';
import { html } from './html.js';

describe('html template', () => {
  it('escapes everything interpolated', () => {
    const name = `<script>alert('x')</script> & "friends"`;
    expect(html`<p title="${name}">${name}</p>`.value).toBe(
      '<p title="&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;friends&quot;">&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;friends&quot;</p>',
    );
  });

  it('keeps nested templates and lists as markup, and drops empty values', () => {
    const items = ['a', '<b>'].map((item) => html`<li>${item}</li>`);
    expect(html`<ul>${items}</ul>${null}${undefined}${false}${0}`.value).toBe('<ul><li>a</li><li>&lt;b&gt;</li></ul>0');
  });
});

describe('canManage', () => {
  it.each([
    [{ owner: true, permissions: '0' }, true],
    [{ permissions: '8' }, true],
    [{ permissions: '32' }, true],
    [{ permissions: String(0x20 | 0x800) }, true],
    [{ owner: false, permissions: '2048' }, false],
    [{ permissions: '0' }, false],
    // Bits above 2^53 must not be lost to floating point.
    [{ permissions: '562949953421312' }, false],
  ])('%j -> %s', (guild, expected) => {
    expect(canManage(guild)).toBe(expected);
  });
});
