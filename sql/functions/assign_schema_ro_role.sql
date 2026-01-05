drop function if exists acm_tools.assign_schema_ro_role (text, text, text);

create or replace function acm_tools.assign_schema_ro_role (p_schema_name text,
                                                            p_ro_user text,
                                                            p_password text default null,
                                                            p_update_search_path boolean default true)
returns text language plpgsql as
--security invoker
$si$
declare
  v_sql text;
begin
  select acm_tools.assign_schema_role (p_schema_name, 'read_only', p_ro_user, p_password, p_update_search_path)
    into v_sql;
  return v_sql;
end; $si$;

revoke execute on function acm_tools.assign_schema_ro_role from public;
