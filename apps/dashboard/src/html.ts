/** Markup that is already safe to put in a page. Only `html` and `escapeHtml` should create it. */
export class Html {
  constructor(readonly value: string) {}
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

type Value = string | number | Html | readonly Html[] | null | undefined | false;

/**
 * Template tag for every page. Anything interpolated is escaped unless it is already
 * `Html`, so text from Discord or the database can't turn into markup.
 */
export function html(strings: TemplateStringsArray, ...values: Value[]): Html {
  let out = strings[0] ?? '';
  values.forEach((value, i) => {
    if (value instanceof Html) out += value.value;
    else if (typeof value === 'string' || typeof value === 'number') out += escapeHtml(String(value));
    else if (value) out += value.map((part) => part.value).join('');
    out += strings[i + 1] ?? '';
  });
  return new Html(out);
}
