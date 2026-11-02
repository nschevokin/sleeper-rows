-- Weekly complaint trends per make/model/year/component group.
-- n_* are counts of attacker-influenceable rows (bounded magnitude => structured at most).
-- avg_severity comes from the LLM enrichment step's schema-checked integer.
-- top_summary is LLM-written free text derived from an untrusted narrative => untrusted.
SELECT
  s.make_norm                                         AS make,
  s.model_norm                                        AS model,
  s.model_year                                        AS model_year,
  s.component_group                                   AS component_group,
  CAST(date_trunc('week', s.received_date) AS DATE)   AS week_start,
  CAST(count(*) AS BIGINT)                            AS n_complaints,
  CAST(sum(CASE WHEN s.crash THEN 1 ELSE 0 END) AS BIGINT) AS n_crash,
  CAST(sum(CASE WHEN s.fire THEN 1 ELSE 0 END) AS BIGINT) AS n_fire,
  CAST(sum(s.injured) AS BIGINT)                       AS n_injured,
  CAST(sum(s.deaths) AS BIGINT)                        AS n_deaths,
  round(avg(e.severity_llm), 2)                       AS avg_severity,
  max_by(e.summary_llm, e.severity_llm)               AS top_summary
FROM stg_complaints AS s
LEFT JOIN enriched_complaints AS e ON e.complaint_key = s.complaint_key
WHERE s.make_norm <> 'UNKNOWN' AND s.model_year IS NOT NULL AND s.received_date IS NOT NULL
GROUP BY 1, 2, 3, 4, 5
