// Fixture for qualor import sonarqube: loose equality twice and a console call.
export function check(a: number, b: string): boolean {
  if (a == 1) {
    return true;
  }
  console.log(b);
  return b == 'x';
}
