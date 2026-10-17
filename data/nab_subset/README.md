# NAB validation data (Person 1 -> Person 2)

Source: Numenta Anomaly Benchmark (github.com/numenta/NAB). Cleaned: duplicates dropped,
sorted by time, 0 missing values, perfectly regular 5-minute spacing.

## Columns (both CSVs)
| column | meaning |
|---|---|
| `timestamp` | 5-minute timestamps |
| `value` | the metric (CPU % for EC2, temperature for the machine series) |
| `is_labeled_anomaly` | True inside a NAB **anomaly window** (use this as ground truth) |
| `is_anomaly_point` | True at the exact NAB-labeled anomaly timestamp (very few rows) |

## Files
- `machine_temperature_system_failure.csv` - 22,683 rows, 4 anomaly windows (known system failures). **Use as primary validation: anomalies are visible.**
- `ec2_cpu_utilization_24ae8d.csv` - 4,032 rows, 2 anomaly windows. Infrastructure CPU, matches our domain, but has regular daily spikes (~1.5) that are NORMAL, so it's a harder test.

## How to validate
Train Isolation Forest on rows where `is_labeled_anomaly == False`, score all rows, then check how many windows
contain at least one flagged point (window-level recall) and how many flags fall outside windows (false positives).
Single-metric series, so features = `value` (+ optional rolling mean/delta).
