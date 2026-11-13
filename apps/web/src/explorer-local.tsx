// Developer-only fixture remains outside the public Explorer's import graph.
import { ExplorerCanvas } from './explorer-canvas';
import { localExplorerFixture } from './explorer-local-fixture.mjs';
import { validateLocalExplorerFixture } from './explorer-model.mjs';
import type { ExplorerFixture } from './explorer-canvas';

const sample = validateLocalExplorerFixture(localExplorerFixture) as ExplorerFixture;
export function ExplorerLocal() { return <ExplorerCanvas fixture={sample} mode="local" />; }
