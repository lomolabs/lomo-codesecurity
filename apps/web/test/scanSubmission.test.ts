import assert from 'node:assert/strict';
import test from 'node:test';

import { submitScanOnce } from '../src/scanSubmission.ts';

test('a scan command owns one in-flight API submission until its request settles', async () => {
  const ownership = { current: false };
  let apiScans = 0;
  let release: (() => void) | undefined;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const submit = async () => {
    apiScans += 1;
    await pending;
    return { id: 17 };
  };

  const first = submitScanOnce(ownership, submit);
  const duplicate = submitScanOnce(ownership, submit);
  assert.equal(await duplicate, undefined);
  assert.equal(apiScans, 1);
  release?.();
  assert.deepEqual(await first, { id: 17 });
  assert.equal(ownership.current, false);
});
