-- Proxy ground truth: a group is a real trend if NHTSA opened an investigation or issued a
-- recall for the same make/model/year/component group within the label window after the
-- evaluation week. The write-up states that this is a proxy label.
SELECT
  t.eval_week, t.make, t.model, t.model_year, t.component_group,
  EXISTS (
    SELECT 1 FROM gold_actions AS a
    WHERE a.make = t.make AND a.model = t.model AND a.model_year = t.model_year
      AND a.component_group = t.component_group
      AND a.action_date >= t.eval_week
      AND a.action_date <  t.eval_week + INTERVAL $LABEL_WINDOW_DAYS DAY
  ) AS label_real_trend
FROM gold_triage_cases AS t
