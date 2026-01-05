drop function if exists pg_acm.revoke_role(text, text, text);

create or replace function pg_acm.revoke_role (p_schema_name text, p_role text, p_srv_user text)
returns text
language plpgsql as
--security invoker
$si$
declare v_sql text;
begin
  if pg_acm.check_schema_perm(p_schema_name) then
    select pg_acm.revoke_role_sd (
            p_schema_name,
            p_role,
            p_srv_user) into v_sql;
    return v_sql;
  else
     raise exception 'You are not allowed to manage roles in schema %', p_schema_name;
 end if;
end; $si$;
revoke execute on function pg_acm.revoke_role from public;
