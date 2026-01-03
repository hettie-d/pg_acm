create or replace function acm_tools.enable_security(p_drop_trigger boolean default true)
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
       execute function acm_tools.fix_owner_grants();
  
  create event trigger create_roles_for_schema 
     on ddl_command_end
     when tag in ('CREATE SCHEMA')
        execute function acm_tools.create_roles_for_schema();
  
  create event trigger drop_roles_for_schema 
     on sql_drop
     when tag in ('DROP SCHEMA')
        execute function acm_tools.drop_roles_for_schema();
  $trg$;
end if;
v_db_owner:=(select
                pg_catalog.pg_get_userbyid(d.datdba)
             from pg_catalog.pg_database d
             where d.datname =current_database());
v_sql:= $$grant execute on function acm_tools.create_cust_account to $$||v_db_owner||$$;$$;

v_sql:=v_sql||$$grant usage on schema acm_tools to $$||v_db_owner||$$;
grant execute on function acm_tools.check_stack to $$||v_db_owner||$$;
grant execute on function acm_tools.create_schema to $$||v_db_owner||$$;
grant execute on function acm_tools.create_schema_sd to $$||v_db_owner||$$;
grant execute on function acm_tools.drop_schema_roles_sd to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_schema_role to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_schema_role_sd to $$||v_db_owner||$$;
grant execute on function acm_tools.create_role to $$||v_db_owner||$$;
grant execute on function acm_tools.create_role_for_schema to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_schema_app_role to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_account_role to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_schema_schema_owner_role to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_schema_ro_role to $$||v_db_owner||$$;
grant execute on function acm_tools.revoke_role to $$||v_db_owner||$$;
grant execute on function acm_tools.revoke_role_sd to $$||v_db_owner||$$;
grant execute on function acm_tools.revoke_schema_app_role to $$||v_db_owner||$$;
grant execute on function acm_tools.revoke_schema_schema_owner_role to $$||v_db_owner||$$;
grant execute on function acm_tools.revoke_schema_ro_role to $$||v_db_owner||$$;
grant execute on function acm_tools.check_schema_perm to $$||v_db_owner||$$;
grant execute on function acm_tools.assign_role(text, text, text) to $$||v_db_owner||$$;
grant execute on function acm_tools.terminate_process to $$||v_db_owner;

execute v_sql;
return v_sql;
end;
$body$;

revoke execute on function acm_tools.enable_security from public;
