-- One row per (evaluation week, group) with at least 3 complaints in the last 28 days.
-- Features only: the label lives in gold_triage_labels and is never visible to agents.
WITH bounds AS (
  SELECT min(week_start) AS w0, max(week_start) AS w1 FROM gold_trends
),
eval AS (
  SELECT CAST(t.w AS DATE) AS eval_week
  FROM bounds, generate_series(
         w0 + INTERVAL 56 DAY, w1 - INTERVAL $LABEL_WINDOW_DAYS DAY, INTERVAL 28 DAY) AS t(w)
),
agg AS (
SELECT
  e.eval_week                                         AS eval_week,
  g.make                                              AS make,
  g.model                                             AS model,
  g.model_year                                        AS model_year,
  g.component_group                                   AS component_group,
  CAST(sum(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.n_complaints ELSE 0 END) AS BIGINT) AS n_4w,
  CAST(sum(CASE WHEN g.week_start <  e.eval_week - INTERVAL 28 DAY
            AND g.week_start >= e.eval_week - INTERVAL 182 DAY THEN g.n_complaints ELSE 0 END) AS BIGINT) AS n_prior_22w,
  CAST(sum(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.n_injured ELSE 0 END) AS BIGINT) AS injured_4w,
  CAST(sum(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.n_deaths ELSE 0 END) AS BIGINT) AS deaths_4w,
  CAST(sum(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.n_fire ELSE 0 END) AS BIGINT) AS fire_4w,
  round(avg(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.avg_severity END), 2) AS avg_severity_4w,
  max_by(g.top_summary, g.week_start)                 AS sample_summary
FROM eval AS e
JOIN gold_trends AS g ON g.week_start < e.eval_week
GROUP BY 1, 2, 3, 4, 5
HAVING sum(CASE WHEN g.week_start >= e.eval_week - INTERVAL 28 DAY THEN g.n_complaints ELSE 0 END) >= 3
)
SELECT
  eval_week, make, model, model_year, component_group, n_4w, n_prior_22w,
  injured_4w, deaths_4w, fire_4w, avg_severity_4w, sample_summary,
  round(n_4w / greatest(n_prior_22w / 22.0 * 4, 0.5), 2) AS surge_ratio
FROM agg
