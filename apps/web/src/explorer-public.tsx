import { useEffect, useState } from 'react';
import { ExplorerCanvas } from './explorer-canvas';
import { explorerPublicUrls, validatePublicExplorerPayload } from './explorer-public-model.mjs';

const toHex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
async function readPublicFixture(signal: AbortSignal) {
  const paths = explorerPublicUrls(import.meta.env.BASE_URL);
  const [recordsResponse, manifestResponse] = await Promise.all([
    fetch(paths.records, { signal, cache: 'no-store' }),
    fetch(paths.manifest, { signal, cache: 'no-store' }),
  ]);
  if (!recordsResponse.ok || !manifestResponse.ok) throw Error('Reviewed fictional Explorer files unavailable');
  const [dataBytes, manifest] = await Promise.all([
    recordsResponse.arrayBuffer(), manifestResponse.json(),
  ]);
  const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', dataBytes)));
  if (digest !== (manifest as { sha256?: string })?.sha256) throw Error('Fictional Explorer data integrity mismatch');
  const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(dataBytes));
  return validatePublicExplorerPayload(document, manifest, dataBytes.byteLength);
}
export function ExplorerPublic() {
  const [sample, setSample] = useState<ReturnType<typeof validatePublicExplorerPayload> | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    readPublicFixture(controller.signal).then(result => { if (!controller.signal.aborted) setSample(result); })
      .catch(reason => { if (!controller.signal.aborted) setError(String(reason?.message || reason)); });
    return () => controller.abort();
  }, []);
  if (error) return <section className="status" role="alert"><h1>Fictional Explorer unavailable.</h1><p>Publication data did not pass verification. No substitute CVE records will be shown.</p></section>;
  if (!sample) return <section className="status" role="status">Checking approved fictional Explorer data...</section>;
  return <ExplorerCanvas fixture={sample} mode="public" />;
}
