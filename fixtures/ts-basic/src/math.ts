// Small math helpers used by the ts-basic fixture.
export function clamp(value: number, min: number, max: number): number {
  if (value < min) {
    return min;
  } else if (value > max) {
    return max;
  }
  return value;
}

export function isZero(value: number): boolean {
  return value == 0;
}

export function sum(values: number[]): number {
  const unused = values.length;
  let total = 0;
  for (const v of values) {
    if (v > 0 && Number.isFinite(v)) {
      total += v;
    }
  }
  console.log(total);
  return total;
}
