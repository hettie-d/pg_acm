begin;

do $$
declare
  v_trigger record;
begin
  for v_trigger in
    select evtname
      from pg_event_trigger
     where
      evtname in (
          'disable_event_triggers', 
          'enable_event_triggers',
          'create_roles_for_schema', 
          'drop_roles_for)schema',
          'rename_roles_for_schema',
          'fix_owner_grants')
  loop
    execute format('drop event trigger %I ', v_trigger.evtname);
  end loop;
end;
$$;
	
create schema if not exists acm_tools;

\ir sql/tables/allowed_role.sql
\ir sql/tables/account_role.sql
\ir sql/tables/killed_processes.sql
\ir sql/event_triggers/event_trigger_functions.sql
\ir sql/functions/check_stack.sql
\ir sql/functions/check_schema_perm.sql
\ir sql/functions/create_cust_account.sql
\ir sql/functions/create_schema.sql
\ir sql/functions/create_schema_sd.sql
\ir sql/functions/drop_schema_roles_sd.sql
\ir sql/functions/create_role.sql
\ir sql/functions/create_role_for_schema.sql
\ir sql/functions/assign_account_role.sql 
\ir sql/functions/assign_role.sql
\ir sql/functions/assign_schema_app_role.sql
\ir sql/functions/assign_schema_role_sd.sql
\ir sql/functions/assign_schema_role.sql
\ir sql/functions/assign_schema_ro_role.sql
\ir sql/functions/assign_schema_schema_owner_role.sql
\ir sql/functions/enable_security.sql
\ir sql/functions/revoke_role_sd.sql
\ir sql/functions/revoke_role.sql
\ir sql/functions/revoke_schema_app_role.sql
\ir sql/functions/revoke_schema_ro_role.sql
\ir sql/functions/revoke_schema_schema_owner_role.sql
\ir sql/functions/terminate_process.sql
\ir sql/functions/list_account_schemas.sql
\ir sql/procedures/public_to_private.sql
\ir sql/procedures/reset_schema_owner.sql
\ir sql/packages/list_users_privs.sql
\ir sql/packages/list_schemas_roles_flat.sql

do $$
declare
  v_cnt int;
  v_rec record;
begin
	 select
    count(*) into v_cnt
  from
    pg_event_trigger
  where
    evtname = 'fix_owner_grants';
  if v_cnt > 0 then
     perform acm_tools.enable_security;
  end if;  
   for v_rec in (select substr(account_role_name, 1, length(account_role_name)-position (reverse('_owner') in reverse(account_role_name))-6) as account 
                from acm_tools.account_role) 
     loop
        perform acm_tools.create_cust_account(v_rec.account);
    end loop;
end;
$$;
commit;

