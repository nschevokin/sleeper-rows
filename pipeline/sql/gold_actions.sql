-- NHTSA actions (investigations and recalls): the ground truth that a pattern was real.
SELECT
  i.NHTSA_ACTION_NUMBER                               AS action_id,
  'investigation'                                     AS kind,
  upper(i.MAKE)                                       AS make,
  upper(i.MODEL)                                      AS model,
  try_cast(i.YEAR AS INTEGER)                         AS model_year,
  upper(split_part(i.COMPNAME, ':', 1))               AS component_group,
  CAST(try_strptime(i.ODATE, '%Y%m%d') AS DATE)       AS action_date
FROM raw_investigations AS i
UNION ALL
SELECT
  r.CAMPNO                                            AS action_id,
  'recall'                                            AS kind,
  upper(r.MAKETXT)                                    AS make,
  upper(r.MODELTXT)                                   AS model,
  try_cast(r.YEARTXT AS INTEGER)                      AS model_year,
  upper(split_part(r.COMPNAME, ':', 1))               AS component_group,
  CAST(try_strptime(COALESCE(NULLIF(r.RCDATE, ''), r.ODATE), '%Y%m%d') AS DATE) AS action_date
FROM raw_recalls AS r
