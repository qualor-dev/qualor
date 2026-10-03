# sarif-samples: third-party notices

These are real SARIF logs captured from real analyzer runs (`fixtures/README.md`), trimmed for
size, and used only as golden input to `sarif-golden.test.ts`. Each is an unmodified excerpt of
that tool's own output (rule ids, messages, categories, tags, `helpUri`) except where noted below.

| Sample               | Produced by                                                                                                                                                                              | Licence                                                                           |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `eslint.sarif`       | ESLint, run over `fixtures/ts-basic`                                                                                                                                                     | MIT                                                                               |
| `pmd.sarif`          | PMD, run over `fixtures/java-basic`                                                                                                                                                      | BSD-style, with Apache-2.0 parts                                                  |
| `spotbugs.sarif`     | SpotBugs, run over `fixtures/java-basic`                                                                                                                                                 | LGPL-2.1                                                                          |
| `findsecbugs.sarif`  | SpotBugs 4.10.4 with FindSecBugs 1.14.0, run over `fixtures/java-security`                                                                                                               | LGPL-2.1 (SpotBugs) and LGPL-3.0 (FindSecBugs's rule descriptions)                |
| `gitleaks.sarif`     | Gitleaks, run over `fixtures/mixed-secrets`                                                                                                                                              | MIT                                                                               |
| `semgrep.sarif`      | Semgrep/OpenGrep, run over `fixtures/mixed-secrets`                                                                                                                                      | LGPL-2.1                                                                          |
| `roslyn.sarif`       | the .NET compiler (Roslyn) and Roslynator.Analyzers, run over `fixtures/csharp-basic`                                                                                                    | MIT (.NET SDK); Apache-2.0 (Roslynator)                                           |
| `roslyn-sonar.sarif` | the .NET compiler (Roslyn), Roslynator.Analyzers and the bundled **SonarAnalyzer.CSharp 9.32.0.97167**, run over `fixtures/csharp-basic`, then merged with `mergeRoslynLogs` and trimmed | MIT (.NET SDK); Apache-2.0 (Roslynator); **LGPL-3.0-only (SonarAnalyzer.CSharp)** |
| `ruff.sarif`         | Ruff 0.16.9, run over `fixtures/python-basic` with qualor-default                                                                                                                        | MIT                                                                               |
| `detekt.sarif`       | detekt 1.23.8, run over `fixtures/kotlin-basic`, rule ids shortened and `properties.ruleset` added by Qualor's conversion (`cli/src/analyzers/detekt-sarif.ts`)                          | Apache-2.0                                                                        |

**`roslyn-sonar.sarif` and SonarSource text.** Qualor's licence boundary (Phase 8A/8B) keeps
SonarSource's own text — rule descriptions, RSPEC prose — out of this repository; the LGPL-3.0
DLLs ship only inside the `qualor/scanner-dotnet` image. In this sample,
every Sonar rule's (`S2325`, `S2930`, `S3400`) `shortDescription`/`fullDescription` text and every
Sonar result's `message` text was replaced with the rule id itself (for example `"S2930"`). Their
rule ids, `helpUri`, `properties.category` and `tags`, and every result's location, are facts
(SonarQube's own rule identity and category strings, and this fixture's own file paths and lines),
not SonarSource's descriptive text, and are kept as the real run produced them. The two non-Sonar
rules in the same sample, `CA5351` (Microsoft, MIT) and `RCS1118` (Roslynator, Apache-2.0), keep
their real text as `roslyn.sarif` already does for the same rule ids.

**`ruff.sarif`.** The rule descriptions in it are Ruff's own documentation, MIT; unlike
`roslyn-sonar.sarif`, nothing is SonarSource text.

**`detekt.sarif`.** The rule descriptions in it are detekt's own documentation, Apache-2.0; nothing is SonarSource text.

**`findsecbugs.sarif`.** The rule descriptions in it are FindSecBugs' and SpotBugs' own documentation; nothing is SonarSource text.
