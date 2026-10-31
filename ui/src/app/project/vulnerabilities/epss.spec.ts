import { epssPercent } from './epss';

describe('epssPercent', () => {
  it('reads a score below 0.1% as <0.1%', () => {
    expect(epssPercent(0.0004)).toBe('<0.1%');
  });

  it('shows one decimal from 0.1% up', () => {
    expect(epssPercent(0.001)).toBe('0.1%');
    expect(epssPercent(0.42)).toBe('42.0%');
    expect(epssPercent(1)).toBe('100.0%');
  });
});
