drop function if exists acm_tools.revoke_role(text, text, text);

create or replace function acm_tools.revoke_role (p_schema_name text, p_role text, p_srv_user text)
returns text
language plpgsql as
--security invoker
$si$
declare v_sql text;
begin
  if acm_tools.check_schema_perm(p_schema_name) then
    select acm_tools.revoke_role_sd (
            p_schema_name,
            p_role,
            p_srv_user) into v_sql;
    return v_sql;
  else
     raise exception 'You are not allowed to manage roles in schema %', p_schema_name;
 end if;
end; $si$;
revoke execute on function acm_tools.revoke_role from public;
