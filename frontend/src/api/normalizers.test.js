import assert from "node:assert/strict";
import test from "node:test";

import { normalizeAnalysisProgress } from "./normalizers.js";


test("normalizes legacy v1 progress without undefined counters", () => {
  const progress = normalizeAnalysisProgress({
    analysis_run_id: 1,
    status: "running",
    total_chunks: 2,
    running_chunks: 1,
    chunks: [{ sequence: 1, language: "python", status: "running" }],
  });

  assert.equal(progress.pipelineVersion, "chunk_v1");
  assert.equal(progress.totalChunks, 2);
  assert.equal(progress.failedChunks, 0);
  assert.equal(progress.chunks[0].resultCount, 0);
  assert.equal(Number.isNaN(progress.progressPercent), false);
});


test("normalizes repository v2 mixed progress and incomplete coverage", () => {
  const progress = normalizeAnalysisProgress({
    analysis_run_id: 2,
    pipeline_version: "repository_v2",
    status: "running",
    progress_percent: 75,
    total_chunks: 1,
    running_chunks: 1,
    result_count: 3,
    raw_occurrence_count: 5,
    coverage_complete: false,
    executions: [{ scope_kind: "repository", coverage_complete: false }],
    chunks: [{ sequence: 1, language: "mixed", status: "running", result_count: 3 }],
  });

  assert.equal(progress.pipelineVersion, "repository_v2");
  assert.equal(progress.chunks[0].language, "mixed");
  assert.equal(progress.resultCount, 3);
  assert.equal(progress.rawOccurrenceCount, 5);
  assert.equal(progress.coverageComplete, false);
  assert.equal(progress.executions[0].coverage_complete, false);
  assert.equal(Number.isNaN(progress.progressPercent), false);
});
