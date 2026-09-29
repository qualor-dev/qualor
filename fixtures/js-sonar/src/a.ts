// Small handlers used by the js-sonar fixture.
export function emptyHandler(): void {
}

export function pick(value: number): number {
  if (value > 0) {
    return 1;
  } else if (value < 0) {
    return 1;
  }
  return 0;
}

export function allSame(value: number, sink: number[]): void {
  if (value === 1) {
    sink.push(1);
  } else if (value === 2) {
    sink.push(1);
  } else {
    sink.push(1);
  }
}
