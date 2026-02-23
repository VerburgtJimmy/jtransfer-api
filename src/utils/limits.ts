export function exceedsTotalLimit(
  currentTotal: number,
  increment: number,
  maxTotal: number
): boolean {
  return currentTotal + increment > maxTotal;
}
