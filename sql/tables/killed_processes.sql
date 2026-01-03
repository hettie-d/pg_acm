create table if not exists acm_tools.killed_processes (
  pid int,
  usename text,
  query text,
  time_killed timestamptz
);
