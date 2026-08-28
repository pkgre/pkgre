'use strict';

const { createHash } = require('node:crypto');
const { Worker } = require('node:worker_threads');

const mode = process.argv[2];
if (mode !== 'baseline' && mode !== 'override') {
  throw new Error('usage: node node-worker-contract-probe.cjs baseline|override');
}

const expectedResourceLimits = {
  maxOldGenerationSizeMb: 192,
  maxYoungGenerationSizeMb: 32,
  codeRangeSizeMb: 32,
  stackSizeMb: 4,
};
const workerSource = String.raw`
'use strict';
const { createHash } = require('node:crypto');
const { parentPort, resourceLimits } = require('node:worker_threads');
parentPort.on('message', (message) => {
  if (message.kind !== 'transfer') throw new Error('unexpected probe message');
  const bytes = new Uint8Array(message.buffer);
  parentPort.postMessage({
    kind: 'transfer-result',
    byteLength: message.buffer.byteLength,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
});
parentPort.postMessage({ kind: 'ready', execArgv: process.execArgv, resourceLimits });
`;

function nextMessage(worker, kind) {
  return new Promise((resolve, reject) => {
    function cleanup() {
      worker.off('error', onError);
      worker.off('exit', onExit);
      worker.off('message', onMessage);
    }
    function onError(error) {
      cleanup();
      reject(error);
    }
    function onExit(code) {
      cleanup();
      reject(new Error(`worker exited before ${kind}: ${code}`));
    }
    function onMessage(message) {
      if (message.kind !== kind) return;
      cleanup();
      resolve(message);
    }
    worker.on('error', onError);
    worker.on('exit', onExit);
    worker.on('message', onMessage);
  });
}

async function main() {
  const worker = new Worker(workerSource, {
    eval: true,
    execArgv: [],
    resourceLimits: expectedResourceLimits,
  });
  try {
    const ready = await nextMessage(worker, 'ready');
    const heap = await worker.getHeapStatistics();
    const result = {
      mode,
      nodeVersion: process.version,
      nodeOptionsPresent: Object.prototype.hasOwnProperty.call(process.env, 'NODE_OPTIONS'),
      parentExecArgv: process.execArgv,
      parentResourceLimitsReadback: worker.resourceLimits,
      workerExecArgv: ready.execArgv,
      workerResourceLimitsReadback: ready.resourceLimits,
      workerHeapSizeLimitBytes: heap.heap_size_limit,
    };
    if (mode === 'baseline') {
      const buffer = new ArrayBuffer(32);
      const byteView = new Uint8Array(buffer);
      const wordView = new Uint32Array(buffer);
      for (let index = 0; index < byteView.length; index += 1) byteView[index] = index;
      const expectedSha256 = createHash('sha256').update(byteView).digest('hex');
      const transferred = nextMessage(worker, 'transfer-result');
      worker.postMessage({ kind: 'transfer', buffer }, [buffer]);
      const transferResult = await transferred;
      result.transfer = {
        expectedSha256,
        receiverByteLength: transferResult.byteLength,
        receiverSha256: transferResult.sha256,
        senderArrayBufferByteLength: buffer.byteLength,
        senderByteViewByteLength: byteView.byteLength,
        senderWordViewByteLength: wordView.byteLength,
      };
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await worker.terminate();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
