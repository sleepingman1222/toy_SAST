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
    retry_count: 3,
    engine_retry_count: 2,
    normalization_retry_count: 1,
    executions: [{ scope_kind: "repository", coverage_complete: false }],
    languages: [{
      language: "python",
      file_count: 2,
      coverage: {
        discovered_supported: 2,
        scanned: 1,
        ignored_by_policy: 0,
        ignored_by_semgrep: 0,
        oversized: 0,
        engine_error: 0,
        missing_from_engine_report: 1,
        unaccounted: 0,
        coverage_complete: false,
      },
    }],
    chunks: [{ sequence: 1, language: "mixed", status: "running", result_count: 3 }],
  });

  assert.equal(progress.pipelineVersion, "repository_v2");
  assert.equal(progress.chunks[0].language, "mixed");
  assert.equal(progress.resultCount, 3);
  assert.equal(progress.rawOccurrenceCount, 5);
  assert.equal(progress.coverageComplete, false);
  assert.equal(progress.retryCount, 3);
  assert.equal(progress.engineRetryCount, 2);
  assert.equal(progress.normalizationRetryCount, 1);
  assert.equal(progress.executions[0].coverage_complete, false);
  assert.equal(progress.languages[0].fileCount, 2);
  assert.equal(progress.languages[0].total, 2);
  assert.equal(progress.languages[0].terminal, 1);
  assert.equal(progress.languages[0].progressPercent, 50);
  assert.equal(progress.languages[0].coverage.scanned, 1);
  assert.equal(progress.languages[0].coverage.coverageComplete, false);
  assert.equal(Number.isNaN(progress.progressPercent), false);
});
