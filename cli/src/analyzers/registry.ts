import { eslintAnalyzer } from './eslint';
import { gitleaksAnalyzer } from './gitleaks';
import { pmdAnalyzer } from './pmd';
import { roslynAnalyzer } from './roslyn';
import { semgrepAnalyzer } from './semgrep';
import { sonarjsAnalyzer } from './sonarjs';
import { spotbugsAnalyzer } from './spotbugs';
import { trivyAnalyzer } from './trivy';
import type { Analyzer } from './types';

/** The built-in analyzers of CLI steps 8–12, in the order of config.md §3. */
export function builtinAnalyzers(): Analyzer[] {
  return [
    eslintAnalyzer,
    sonarjsAnalyzer,
    pmdAnalyzer,
    spotbugsAnalyzer,
    semgrepAnalyzer,
    gitleaksAnalyzer,
    trivyAnalyzer,
    roslynAnalyzer,
  ];
}
