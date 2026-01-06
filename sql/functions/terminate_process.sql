create or replace function acm_tools.terminate_process(p_pid int)
returns boolean
language plpgsql
security definer as
$function$
declare
v_usename text;
v_state text;
v_query text;
begin
select usename, state, query into v_usename, v_state from pg_stat_activity where pid=p_pid and datname=current_database();
if v_usename is null
  or v_usename like 'pg_%'
  or v_usename in ('autocat', 'drwdba_owner', 'nagios', 'postgres')
then return false;
end if;
insert into acm_tools.killed_processes
  (pid,
    usename,
    query,
    time_killed) values
  (p_pid,
  v_usename,
  v_query,
  now());
return pg_terminate_backend(p_pid);
end;
$function$;

revoke execute on function acm_tools.terminate_process(p_pid int) from public;
