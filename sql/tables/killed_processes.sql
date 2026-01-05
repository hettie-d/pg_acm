create table if not exists pg_acm.killed_processes (
  pid int,
  usename text,
  query text,
  time_killed timestamptz
);
