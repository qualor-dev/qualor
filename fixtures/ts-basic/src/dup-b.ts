export const DEFAULT_CURRENCY = 'EUR';

export function formatInvoice(items: { name: string; qty: number; price: number }[], currency: string): string {
  const lines: string[] = [];
  let subtotal = 0;
  for (const item of items) {
    const lineTotal = item.qty * item.price;
    subtotal += lineTotal;
    lines.push(`${item.name.padEnd(20)} ${String(item.qty).padStart(4)} ${lineTotal.toFixed(2)} ${currency}`);
  }
  const tax = Math.round(subtotal * 0.2 * 100) / 100;
  const total = subtotal + tax;
  lines.push(`${'Subtotal'.padEnd(25)} ${subtotal.toFixed(2)} ${currency}`);
  lines.push(`${'Tax (20%)'.padEnd(25)} ${tax.toFixed(2)} ${currency}`);
  lines.push(`${'Total'.padEnd(25)} ${total.toFixed(2)} ${currency}`);
  return lines.join('\n');
}
