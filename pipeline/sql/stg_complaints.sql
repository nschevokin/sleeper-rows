-- Staging for complaints. Free-text vehicle names are replaced by members of a closed,
-- operator-approved vocabulary via a lookup join, so make_norm/model_norm derive only from
-- trusted reference columns (explicit flow). The join condition is an implicit flow from
-- untrusted text and is reported by the lineage tool as "selection influence".
SELECT
  c._key                                              AS complaint_key,
  c.ODINO                                             AS odino,
  c.COMPDESC                                          AS compdesc,
  upper(split_part(c.COMPDESC, ':', 1))               AS component_group,
  COALESCE(v.make, 'UNKNOWN')                         AS make_norm,
  COALESCE(v.model, 'UNKNOWN')                        AS model_norm,
  CASE WHEN try_cast(c.YEARTXT AS INTEGER) BETWEEN 1950 AND 2030
       THEN try_cast(c.YEARTXT AS INTEGER) END        AS model_year,
  CAST(try_strptime(c.FAILDATE, '%Y%m%d') AS DATE)    AS fail_date,
  CAST(try_strptime(c.LDATE, '%Y%m%d') AS DATE)       AS received_date,
  c.CRASH = 'Y'                                       AS crash,
  c.FIRE = 'Y'                                        AS fire,
  COALESCE(try_cast(c.INJURED AS INTEGER), 0)         AS injured,
  COALESCE(try_cast(c.DEATHS AS INTEGER), 0)          AS deaths,
  try_cast(c.MILES AS INTEGER)                        AS miles,
  c.CDESCR                                            AS cdescr
FROM raw_complaints AS c
LEFT JOIN ref_vehicles AS v
  ON upper(c.MAKETXT) = v.make AND upper(c.MODELTXT) = v.model
