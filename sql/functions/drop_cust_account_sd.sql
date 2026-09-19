create or replace function acm_tools.drop_cust_account_sd (p_acct_name text)
returns text
language plpgsql security definer
as $body$
declare
v_sql text;
v_sql_role text;
v_db_owner text;
v_cnt int;
v_rec record;
begin
  v_db_owner=(SELECT
  pg_catalog.pg_get_userbyid(d.datdba)
  FROM pg_catalog.pg_database d
  WHERE d.datname =current_database());
  v_sql_role :=p_acct_name||'_owner';

   v_sql:=format(
   $$ revoke usage on schema acm_tools from %s;
    revoke select on acm_tools.account_role from %s;
	revoke execute on all functions in schema acm_tools from %s;
	revoke execute on all procedures in schema acm_tools from %s;
    revoke create on database %s from %s;
    $$,
    v_sql_role,
    v_sql_role,
	  v_sql_role,
	  v_sql_role,
    current_database(),
    v_sql_role);
    v_sql:=v_sql ||'; delete from acm_tools.account_role where account_role_name ='||quote_literal(v_sql_role)||
 '; drop role  '||v_sql_role;
execute v_sql;
return v_sql;
end;
$body$;
revoke execute on function acm_tools.drop_cust_account_sd from public;

