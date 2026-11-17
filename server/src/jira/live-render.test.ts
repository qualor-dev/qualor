import { describe, expect, it } from 'vitest';
import { advisoryUrl } from './markup';
import { forbiddenMarkup } from './live-render';

describe('the live check forbids real markup only', () => {
  it('stays quiet on correct rendered output', () => {
    const href = advisoryUrl('https://evil.example/a?c={color:red}x{color}&i=!x!') ?? '';
    expect(href).toContain('%7Bcolor:red%7D');
    const html =
      `<h3 id="x">CVE</h3><p>Advisory: <a href="${href.replaceAll('&', '&amp;')}" class="external-link">CVE</a></p>` +
      '<div class="panel" style="border-color: #ccc;border-width: 1px;"><div class="panelContent" style="background-color: #f0f0f0;">' +
      '<pre>{html}&lt;b&gt;x&lt;/b&gt;{html} {color:red}x{color}</pre></div></div>';
    expect(forbiddenMarkup(html)).toEqual([]);
  });

  it('fires on real colouring, images, bold and scripts', () => {
    expect(forbiddenMarkup('<p><font color="red">x</font></p>')).toEqual([
      'a coloured text (font)',
    ]);
    expect(forbiddenMarkup('<span style="color: red">x</span>')).toEqual([
      'a coloured text (style)',
    ]);
    expect(forbiddenMarkup('<span style="border-color:#ccc; color:#f00">x</span>')).toEqual([
      'a coloured text (style)',
    ]);
    expect(forbiddenMarkup('<img src="x"><b>x</b><script>1</script>').sort()).toEqual(
      ['a script', 'an image', 'bold or italic'].sort(),
    );
  });
});
