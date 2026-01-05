create or replace function pg_acm.enable_security(p_drop_trigger boolean default true)
returns text language plpgsql as
$body$
declare
v_db_owner text;
v_sql text;
begin
if p_drop_trigger then
  execute $trg$
  drop event trigger if exists fix_owner_grants;
  drop event trigger if exists create_roles_for_schema;
  drop event trigger if exists drop_roles_for_schema;
  create event trigger fix_owner_grants
     on ddl_command_end
     when tag in ('CREATE TABLE','CREATE TABLE AS','CREATE VIEW', 'CREATE MATERIALIZED VIEW',
     'CREATE SEQUENCE', 'CREATE FUNCTION', 'CREATE PROCEDURE', 'CREATE TYPE', 'CREATE FOREIGN TABLE')
       execute function pg_acm.fix_owner_grants();

  create event trigger create_roles_for_schema
     on ddl_command_end
     when tag in ('CREATE SCHEMA')
        execute function pg_acm.create_roles_for_schema();

  create event trigger drop_roles_for_schema
     on sql_drop
     when tag in ('DROP SCHEMA')
        execute function pg_acm.drop_roles_for_schema();
  $trg$;
end if;
v_db_owner:=(select
                pg_catalog.pg_get_userbyid(d.datdba)
             from pg_catalog.pg_database d
             where d.datname =current_database());
v_sql:= $$grant execute on function pg_acm.create_cust_account to $$||v_db_owner||$$;$$;

v_sql:=v_sql||$$grant usage on schema pg_acm to $$||v_db_owner||$$;
grant execute on function pg_acm.check_stack to $$||v_db_owner||$$;
grant execute on function pg_acm.create_schema to $$||v_db_owner||$$;
grant execute on function pg_acm.create_schema_sd to $$||v_db_owner||$$;
grant execute on function pg_acm.drop_schema_roles_sd to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_schema_role to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_schema_role_sd to $$||v_db_owner||$$;
grant execute on function pg_acm.create_role to $$||v_db_owner||$$;
grant execute on function pg_acm.create_role_for_schema to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_schema_app_role to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_account_role to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_schema_schema_owner_role to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_schema_ro_role to $$||v_db_owner||$$;
grant execute on function pg_acm.revoke_role to $$||v_db_owner||$$;
grant execute on function pg_acm.revoke_role_sd to $$||v_db_owner||$$;
grant execute on function pg_acm.revoke_schema_app_role to $$||v_db_owner||$$;
grant execute on function pg_acm.revoke_schema_schema_owner_role to $$||v_db_owner||$$;
grant execute on function pg_acm.revoke_schema_ro_role to $$||v_db_owner||$$;
grant execute on function pg_acm.check_schema_perm to $$||v_db_owner||$$;
grant execute on function pg_acm.assign_role(text, text, text) to $$||v_db_owner||$$;
grant execute on function pg_acm.terminate_process to $$||v_db_owner;

execute v_sql;
return v_sql;
end;
$body$;

revoke execute on function pg_acm.enable_security from public;
