export interface GeneratedFile {
  path: string;
  text: string;
}

/**
 * Deterministic TypeScript sources: every function is distinct, except that file 20k+1 starts
 * with a verbatim copy of the first two functions of file 20k. Expected duplication is exactly
 * one group per 20 files, and every file has 239 lines when functionsPerFile is 20.
 */
export function generateSources(
  files: number,
  functionsPerFile: number,
  seed = 1,
): GeneratedFile[] {
  let state = seed;
  const next = () => {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    return state % 1000;
  };
  const fn = (name: string): string[] => {
    const acc = `acc${next()}`;
    return [
      `export function ${name}(input: number[], limit: number): number {`,
      `  let ${acc} = ${next()};`,
      `  for (const value of input) {`,
      `    if (value > limit && value % ${(next() % 7) + 2} === 0) {`,
      `      ${acc} += value * ${next()};`,
      `    } else if (value < ${next()}) {`,
      `      ${acc} -= ${next()};`,
      `    }`,
      `  }`,
      `  return ${acc} > ${next()} ? ${acc} : -${acc};`,
      `}`,
      ``,
    ];
  };
  const out: GeneratedFile[] = [];
  let copied: string[] = [];
  for (let f = 0; f < files; f++) {
    const lines: string[] = [];
    for (let i = 0; i < functionsPerFile; i++) {
      if (f % 20 === 1 && i < 2) {
        if (i === 0) lines.push(...copied);
        continue;
      }
      const body = fn(`f${f}_${i}`);
      if (f % 20 === 0 && i === 0) copied = [...body];
      if (f % 20 === 0 && i === 1) copied.push(...body);
      lines.push(...body);
    }
    out.push({ path: `src/m${f}.ts`, text: lines.join('\n') });
  }
  return out;
}
