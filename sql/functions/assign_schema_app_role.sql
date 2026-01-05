drop function if exists acm_tools.assign_schema_app_role (text, text, text);
create or replace function acm_tools.assign_schema_app_role (p_schema_name text,
                                                             p_srv_user text,
                                                             p_password text default null,
                                                             p_update_search_path boolean default true
)
--security invoker
RETURNS text language plpgsql as
$si$
declare
v_sql text;
begin
  select acm_tools.assign_schema_role (p_schema_name, 'read_write', p_srv_user, p_password, p_update_search_path)
  into v_sql;
return v_sql;
end; $si$;

revoke execute on function acm_tools.assign_schema_app_role from public;
