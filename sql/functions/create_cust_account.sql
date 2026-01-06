create or replace function acm_tools.create_cust_account (p_acct_name text)
returns text
language plpgsql security definer
as $body$
declare
v_sql text;
v_sql_role text;
v_db_owner text;
v_cnt int;
begin
  v_db_owner=(
    select pg_catalog.pg_get_userbyid(d.datdba)
    from pg_catalog.pg_database d
    where d.datname =current_database());
  v_sql_role :=p_acct_name||'_owner';
  select count(*) into v_cnt from pg_roles where rolname=v_sql_role;
  if v_cnt=0 then --new role
    execute $$create role $$|| v_sql_role;
  end if;
  insert into acm_tools.account_role values (v_sql_role) on conflict do nothing;
  v_sql:=format($sql$
  grant usage on schema acm_tools to %s;
  grant select on acm_tools.account_role to %s;
  grant %s to %s;
  grant execute on function acm_tools.check_schema_perm to %s;
  grant execute on function acm_tools.check_stack to %s;
  grant execute on function acm_tools.create_schema to %s;
  grant execute on function acm_tools.create_schema_sd to %s;
  grant execute on function acm_tools.create_role_for_schema to %s;
  grant execute on function acm_tools.drop_schema_roles_sd to %s;
  grant execute on function acm_tools.assign_schema_role to %s;
  grant execute on function acm_tools.assign_schema_role_sd to %s;
  grant execute on function acm_tools.revoke_role to %s;
  grant execute on function acm_tools.revoke_role_sd to %s;
  grant execute on function acm_tools.assign_schema_app_role to %s;
  grant execute on function acm_tools.assign_schema_schema_owner_role to %s;
  grant execute on function acm_tools.assign_schema_ro_role to %s;
  grant execute on function acm_tools.revoke_schema_app_role to %s;
  grant execute on function acm_tools.revoke_schema_schema_owner_role to %s;
  grant execute on function acm_tools.revoke_schema_ro_role to %s;
  grant create on database %s to %s;
  $sql$,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_db_owner,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  v_sql_role,
  current_database(),
  v_sql_role
  );
execute v_sql;
return v_sql;
end; $body$;

revoke execute on function acm_tools.create_cust_account from public;
