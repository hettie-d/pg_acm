drop function if exists acm_tools.revoke_schema_schema_owner_role (text, text);

create or replace function acm_tools.revoke_schema_schema_owner_role (
  p_schema_name text,
  p_srv_user text)
returns text
as
$func$
declare
v_sql text;
begin
  select acm_tools.revoke_role(p_schema_name, 'schema_owner', p_srv_user)
  into v_sql;
return v_sql;
end;
$func$
language plpgsql;

revoke execute on function acm_tools.revoke_schema_schema_owner_role from public;
