/*
 * frontend/src/api/normalizers.js
 *
 * Backend 응답의 snake_case / legacy field를
 * Frontend가 사용하는 camelCase shape으로 정규화한다.
 *
 * HTTP 요청 책임은 포함하지 않는다.
 */

export function formatApiDateTime(
  value
) {

  if (!value) {
    return "-";
  }


  const date =
    new Date(
      value
    );


  if (
    Number.isNaN(
      date.getTime()
    )
  ) {

    return value;
  }


  const year =
    date.getFullYear();


  const month =
    String(
      date.getMonth() + 1
    ).padStart(
      2,
      "0"
    );


  const day =
    String(
      date.getDate()
    ).padStart(
      2,
      "0"
    );


  const hour =
    String(
      date.getHours()
    ).padStart(
      2,
      "0"
    );


  const minute =
    String(
      date.getMinutes()
    ).padStart(
      2,
      "0"
    );


  return (
    `${year}-${month}-${day} ${hour}:${minute}`
  );
}

export function normalizeSourceVersion(
  source
) {

  return {

    id:
      source.id,

    version:
      source.version,

    language:
      source.language ||
      "",

    sourceType:
      source.source_type ??
      source.sourceType ??
      "",

    sourceFileName:
      source.source_file_name ??
      source.sourceFileName ??
      "",

    repositoryUrl:
      source.repository_url ??
      source.repositoryUrl ??
      "",

    internalPath:
      source.internal_path ??
      source.internalPath ??
      "",

    createdById:
      source.created_by_id ??
      source.createdById ??
      null,

    createdByUsername:
      source.created_by_username ??
      source.createdByUsername ??
      "",

    createdAt:
      formatApiDateTime(
        source.created_at ??
        source.createdAt
      ),
  };
}

export function normalizeVulnerability(
  vulnerability
) {

  return {

    id:
      vulnerability.id,

    securityWeaknessIdentifier:
      vulnerability.security_weakness_identifier ??
      vulnerability.securityWeaknessIdentifier ??
      null,

    securityWeaknessItemNumber:
      vulnerability.security_weakness_item_number ??
      vulnerability.securityWeaknessItemNumber ??
      null,

    ruleId:
      vulnerability.rule_id ??
      vulnerability.ruleId ??
      "",

    name:
      vulnerability.name ||
      "",

    severity:
      vulnerability.severity ||
      "",

    confidence:
      vulnerability.confidence ||
      "",

    filePath:
      vulnerability.file_path ??
      vulnerability.filePath ??
      "",

    line:
      vulnerability.line ??
      null,

    startLine:
      vulnerability.start_line ??
      vulnerability.startLine ??
      vulnerability.line ??
      null,

    startColumn:
      vulnerability.start_column ??
      vulnerability.startColumn ??
      null,

    endLine:
      vulnerability.end_line ??
      vulnerability.endLine ??
      null,

    endColumn:
      vulnerability.end_column ??
      vulnerability.endColumn ??
      null,

    message:
      vulnerability.message ||
      "",

    evidence:
      vulnerability.evidence ||
      "",

    recommendation:
      vulnerability.recommendation ||
      "",

    createdAt:
      formatApiDateTime(
        vulnerability.created_at ??
        vulnerability.createdAt
      ),
  };
}

export function normalizeAnalysisRun(
  analysis
) {

  return {

    id:
      analysis.id,

    projectId:
      analysis.project_id ??
      analysis.projectId ??
      null,

    sourceVersionId:
      analysis.source_version_id ??
      analysis.sourceVersionId ??
      null,

    sequence:
      analysis.sequence,

    status:
      analysis.status ||
      "",

    engine:
      analysis.engine ||
      "Semgrep",

    analysisLanguage:
      analysis.analysis_language ??
      analysis.analysisLanguage ??
      "",

    analysisLanguages:
      Array.isArray(
        analysis.analysis_languages ??
        analysis.analysisLanguages
      )
        ? [
            ...(
              analysis.analysis_languages ??
              analysis.analysisLanguages
            ),
          ]
        : [],

    executedById:
      analysis.executed_by_id ??
      analysis.executedById ??
      null,

    executedByUsername:
      analysis.executed_by_username ??
      analysis.executedByUsername ??
      "",

    startedAt:
      analysis.started_at ||
      analysis.startedAt
        ? formatApiDateTime(
            analysis.started_at ??
            analysis.startedAt
          )
        : null,

    completedAt:
      analysis.completed_at ||
      analysis.completedAt
        ? formatApiDateTime(
            analysis.completed_at ??
            analysis.completedAt
          )
        : null,

    failureReason:
      analysis.failure_reason ??
      analysis.failureReason ??
      "",

    logs:
      analysis.logs ||
      "",

    rawResult:
      analysis.raw_result ??
      analysis.rawResult ??
      null,

    summary:
      analysis.summary ??
      null,

    vulnerabilities:
      (
        analysis.vulnerabilities ||
        []
      ).map(
        normalizeVulnerability
      ),

    createdAt:
      formatApiDateTime(
        analysis.created_at ??
        analysis.createdAt
      ),

    updatedAt:
      formatApiDateTime(
        analysis.updated_at ??
        analysis.updatedAt
      ),
  };
}

export function normalizeAnalysisChunk(
  chunk
) {

  return {

    id:
      chunk.id,

    sequence:
      chunk.sequence ??
      0,

    language:
      chunk.language ||
      "",

    status:
      chunk.status ||
      "",

    fileCount:
      chunk.file_count ??
      chunk.fileCount ??
      0,

    totalBytes:
      chunk.total_bytes ??
      chunk.totalBytes ??
      0,

    retryCount:
      chunk.retry_count ??
      chunk.retryCount ??
      0,

    maxRetries:
      chunk.max_retries ??
      chunk.maxRetries ??
      0,

    resultCount:
      chunk.result_count ??
      chunk.resultCount ??
      0,

    statusReason:
      chunk.status_reason ??
      chunk.statusReason ??
      "",

    startedAt:
      chunk.started_at ||
      chunk.startedAt
        ? formatApiDateTime(
            chunk.started_at ??
            chunk.startedAt
          )
        : null,

    completedAt:
      chunk.completed_at ||
      chunk.completedAt
        ? formatApiDateTime(
            chunk.completed_at ??
            chunk.completedAt
          )
        : null,
  };
}

export function normalizeAnalysisLanguageProgress(
  language
) {

  const rawCoverage =
    language.coverage && typeof language.coverage === "object"
      ? language.coverage
      : null;

  const coverage = rawCoverage
    ? {
        discoveredSupported:
          rawCoverage.discovered_supported ??
          rawCoverage.discoveredSupported ??
          language.file_count ??
          language.fileCount ??
          0,
        scanned: rawCoverage.scanned ?? 0,
        ignoredByPolicy:
          rawCoverage.ignored_by_policy ?? rawCoverage.ignoredByPolicy ?? 0,
        ignoredBySemgrep:
          rawCoverage.ignored_by_semgrep ?? rawCoverage.ignoredBySemgrep ?? 0,
        oversized: rawCoverage.oversized ?? 0,
        engineError:
          rawCoverage.engine_error ?? rawCoverage.engineError ?? 0,
        missingFromEngineReport:
          rawCoverage.missing_from_engine_report ??
          rawCoverage.missingFromEngineReport ??
          0,
        unaccounted: rawCoverage.unaccounted ?? 0,
        coverageComplete:
          rawCoverage.coverage_complete ??
          rawCoverage.coverageComplete ??
          false,
      }
    : null;

  const fileCount =
    language.file_count ??
    language.fileCount ??
    coverage?.discoveredSupported ??
    0;

  const coveredFileCount = coverage
    ? Math.max(
        fileCount -
          coverage.missingFromEngineReport -
          coverage.unaccounted,
        0
      )
    : 0;

  return {

    language:
      language.language ||
      "",

    total:
      language.total ??
      fileCount,

    terminal:
      language.terminal ??
      coveredFileCount,

    active:
      language.active ??
      0,

    pending:
      language.pending ??
      0,

    queued:
      language.queued ??
      0,

    running:
      language.running ??
      0,

    retryPending:
      language.retry_pending ??
      language.retryPending ??
      0,

    completed:
      language.completed ??
      0,

    failed:
      language.failed ??
      0,

    skipped:
      language.skipped ??
      0,

    cancelled:
      language.cancelled ??
      0,

    resultCount:
      language.result_count ??
      language.resultCount ??
      0,

    retryCount:
      language.retry_count ??
      language.retryCount ??
      0,

    progressPercent:
      language.progress_percent ??
      language.progressPercent ??
      (fileCount > 0
        ? Math.round((coveredFileCount / fileCount) * 100)
        : 0),

    fileCount,

    coverage,
  };
}

export function normalizeAnalysisProgress(
  progress
) {

  return {

    analysisRunId:
      progress.analysis_run_id ??
      progress.analysisRunId ??
      null,

    pipelineVersion:
      progress.pipeline_version ??
      progress.pipelineVersion ??
      "chunk_v1",

    status:
      progress.status ||
      "",

    progressPercent:
      progress.progress_percent ??
      progress.progressPercent ??
      0,

    totalChunks:
      progress.total_chunks ??
      progress.totalChunks ??
      0,

    terminalChunks:
      progress.terminal_chunks ??
      progress.terminalChunks ??
      0,

    activeChunks:
      progress.active_chunks ??
      progress.activeChunks ??
      0,

    unknownChunks:
      progress.unknown_chunks ??
      progress.unknownChunks ??
      0,

    pendingChunks:
      progress.pending_chunks ??
      progress.pendingChunks ??
      0,

    queuedChunks:
      progress.queued_chunks ??
      progress.queuedChunks ??
      0,

    runningChunks:
      progress.running_chunks ??
      progress.runningChunks ??
      0,

    retryPendingChunks:
      progress.retry_pending_chunks ??
      progress.retryPendingChunks ??
      0,

    completedChunks:
      progress.completed_chunks ??
      progress.completedChunks ??
      0,

    failedChunks:
      progress.failed_chunks ??
      progress.failedChunks ??
      0,

    skippedChunks:
      progress.skipped_chunks ??
      progress.skippedChunks ??
      0,

    cancelledChunks:
      progress.cancelled_chunks ??
      progress.cancelledChunks ??
      0,

    totalFiles:
      progress.total_files ??
      progress.totalFiles ??
      0,

    totalBytes:
      progress.total_bytes ??
      progress.totalBytes ??
      0,

    resultCount:
      progress.result_count ??
      progress.resultCount ??
      0,

    rawOccurrenceCount:
      progress.raw_occurrence_count ??
      progress.rawOccurrenceCount ??
      0,

    coverageComplete:
      progress.coverage_complete ??
      progress.coverageComplete ??
      null,

    capabilities:
      progress.capabilities ||
      null,

    executions:
      progress.executions || [],

    retryCount:
      progress.retry_count ??
      progress.retryCount ??
      0,

    engineRetryCount:
      progress.engine_retry_count ??
      progress.engineRetryCount ??
      0,

    normalizationRetryCount:
      progress.normalization_retry_count ??
      progress.normalizationRetryCount ??
      0,

    languages:
      (
        progress.languages ||
        []
      ).map(
        normalizeAnalysisLanguageProgress
      ),

    chunks:
      (
        progress.chunks ||
        []
      ).map(
        normalizeAnalysisChunk
      ),

    updatedAt:
      progress.updated_at ||
      progress.updatedAt
        ? formatApiDateTime(
            progress.updated_at ??
            progress.updatedAt
          )
        : null,
  };
}

export function normalizeProject(
  project
) {

  return {

    id:
      project.id,

    name:
      project.name ||
      "",

    description:
      project.description ||
      "",

    createdById:
      project.created_by_id ??
      project.createdById ??
      null,

    createdByUsername:
      project.created_by_username ??
      project.createdByUsername ??
      "",

    createdAt:
      formatApiDateTime(
        project.created_at ??
        project.createdAt
      ),

    updatedAt:
      formatApiDateTime(
        project.updated_at ??
        project.updatedAt
      ),

    currentSourceVersionId:
      project.current_source_version_id ??
      project.currentSourceVersionId ??
      null,


    // ProjectAccess Backend 연결
    assignedUserIds:
      project.assigned_user_ids ??
      project.assignedUserIds ??
      [],

    sourceVersions:
      (
        project.source_versions ??
        project.sourceVersions ??
        []
      ).map(
        normalizeSourceVersion
      ),

    analysisHistory:
      (
        project.analysis_runs ??
        project.analysisHistory ??
        []
      ).map(
        normalizeAnalysisRun
      ),
  };
}

export function normalizeUser(
  user
) {

  return {

    id:
      user.id,

    username:
      user.username ||
      "",

    role:
      user.role ||
      "user",

    isActive:
      user.isActive ??
      user.is_active ??
      false,

    createdAt:
      formatApiDateTime(
        user.createdAt ??
        user.date_joined
      ),

    lastLogin:
      (
        user.lastLogin ??
        user.last_login
      )
        ? formatApiDateTime(
            user.lastLogin ??
            user.last_login
          )
        : null,
  };
}

export function normalizeAdminSummary(
  summary
) {

  return {

    totalUsers:
      summary.total_users ??
      0,

    activeUsers:
      summary.active_users ??
      0,

    totalProjects:
      summary.total_projects ??
      0,

    totalAnalysisRuns:
      summary.total_analysis_runs ??
      0,

    analysisStatus: {

      pending:
        summary.analysis_status
          ?.pending ??
        0,

      running:
        summary.analysis_status
          ?.running ??
        0,

      completed:
        summary.analysis_status
          ?.completed ??
        0,

      failed:
        summary.analysis_status
          ?.failed ??
        0,
    },

    recentAnalyses:
      (
        summary.recent_analyses ||
        []
      ).map(
        (analysis) => ({

          id:
            analysis.id,

          sequence:
            analysis.sequence,

          projectId:
            analysis.project_id ??
            null,

          projectName:
            analysis.project_name ||
            "",

          sourceVersionId:
            analysis.source_version_id ??
            null,

          sourceVersion:
            analysis.source_version ??
            null,

          analysisLanguage:
            analysis.analysis_language ||
            "",

          status:
            analysis.status ||
            "",

          resultCount:
            analysis.result_count ??
            0,

          executedByUsername:
            analysis.executed_by_username ||
            "",

          startedAt:
            analysis.started_at
              ? formatApiDateTime(
                  analysis.started_at
                )
              : null,

          completedAt:
            analysis.completed_at
              ? formatApiDateTime(
                  analysis.completed_at
                )
              : null,

          createdAt:
            analysis.created_at
              ? formatApiDateTime(
                  analysis.created_at
                )
              : null,
        })
      ),
  };
}
