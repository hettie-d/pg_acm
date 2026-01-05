create or replace function pg_acm.create_cust_account (p_acct_name text)
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
  insert into pg_acm.account_role values (v_sql_role) on conflict do nothing;
  v_sql:=format($sql$
  grant usage on schema pg_acm to %s;
  grant select on pg_acm.account_role to %s;
  grant %s to %s;
  grant execute on function pg_acm.check_schema_perm to %s;
  grant execute on function pg_acm.check_stack to %s;
  grant execute on function pg_acm.create_schema to %s;
  grant execute on function pg_acm.create_schema_sd to %s;
  grant execute on function pg_acm.create_role_for_schema to %s;
  grant execute on function pg_acm.drop_schema_roles_sd to %s;
  grant execute on function pg_acm.assign_schema_role to %s;
  grant execute on function pg_acm.assign_schema_role_sd to %s;
  grant execute on function pg_acm.revoke_role to %s;
  grant execute on function pg_acm.revoke_role_sd to %s;
  grant execute on function pg_acm.assign_schema_app_role to %s;
  grant execute on function pg_acm.assign_schema_schema_owner_role to %s;
  grant execute on function pg_acm.assign_schema_ro_role to %s;
  grant execute on function pg_acm.revoke_schema_app_role to %s;
  grant execute on function pg_acm.revoke_schema_schema_owner_role to %s;
  grant execute on function pg_acm.revoke_schema_ro_role to %s;
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
revoke execute on function pg_acm.create_cust_account from public;
