create or replace function pg_acm.revoke_schema_ro_role (p_schema_name text,
p_srv_user text)
RETURNS text
AS
$func$
declare v_sql text;
BEGIN
 select pg_acm.revoke_role(p_schema_name,'read_only', p_srv_user)
 into v_sql;
return v_sql;

END;
$func$
language plpgsql;
revoke execute on function pg_acm.revoke_schema_ro_role from public;
