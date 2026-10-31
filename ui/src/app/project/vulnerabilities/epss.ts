/** An EPSS score in [0, 1] as a percentage with one decimal; below 0.1% it reads "<0.1%". */
export function epssPercent(score: number): string {
  return score < 0.001 ? '<0.1%' : `${(score * 100).toFixed(1)}%`;
}
