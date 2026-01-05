drop function if exists pg_acm.assign_schema_role(text, text, text, text);

create or replace function pg_acm.assign_schema_role (p_schema_name text,
p_role text,
p_srv_user text,
p_password text default null,
p_update_search_path boolean default true)
--security invoker
RETURNS text language plpgsql as
$si$
declare
v_sql text;
begin
  if pg_acm.check_schema_perm(p_schema_name) then
    select pg_acm.assign_schema_role_sd (
            p_schema_name,
            p_role,
            p_srv_user,
            p_password,
            p_update_search_path) into v_sql;
    return v_sql;
  else
     raise exception 'You are not allowed to assign roles in schema %', p_schema_name;
 end if;
end; $si$;
revoke execute on function pg_acm.assign_schema_role from public;
