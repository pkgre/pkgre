export const USAGE = "usage: pkgre-js --help";

export function run(args) {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    return { status: 0, output: `${USAGE}\n` };
  }
  return { status: 1, output: `${USAGE}\n` };
}
