import { detektAnalyzer } from './detekt';
import { eslintAnalyzer } from './eslint';
import { gitleaksAnalyzer } from './gitleaks';
import { gosecAnalyzer, govetAnalyzer, staticcheckAnalyzer } from './golang';
import { htmlhintAnalyzer } from './htmlhint';
import { pmdAnalyzer } from './pmd';
import { roslynAnalyzer } from './roslyn';
import { ruffAnalyzer } from './ruff';
import { semgrepAnalyzer } from './semgrep';
import { sonarjsAnalyzer } from './sonarjs';
import { spotbugsAnalyzer } from './spotbugs';
import { stylelintAnalyzer } from './stylelint';
import { swiftlintAnalyzer } from './swiftlint';
import { trivyAnalyzer } from './trivy';
import type { Analyzer } from './types';

/** The built-in analyzers of CLI steps 8–12, in the order of config.md §3. */
export function builtinAnalyzers(): Analyzer[] {
  return [
    eslintAnalyzer,
    sonarjsAnalyzer,
    ruffAnalyzer,
    pmdAnalyzer,
    spotbugsAnalyzer,
    detektAnalyzer,
    swiftlintAnalyzer,
    semgrepAnalyzer,
    gitleaksAnalyzer,
    trivyAnalyzer,
    roslynAnalyzer,
    stylelintAnalyzer,
    htmlhintAnalyzer,
    staticcheckAnalyzer,
    govetAnalyzer,
    gosecAnalyzer,
  ];
}
