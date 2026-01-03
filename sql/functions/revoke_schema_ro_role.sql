create or replace function acm_tools.revoke_schema_ro_role (p_schema_name text,
p_srv_user text)
RETURNS text
AS
$func$
declare v_sql text;
BEGIN
 select acm_tools.revoke_role(p_schema_name,'read_only', p_srv_user)
 into v_sql;
return v_sql;

END;
$func$
language plpgsql;
revoke execute on function acm_tools.revoke_schema_ro_role from public;
