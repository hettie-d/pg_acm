drop function if exists acm_tools.revoke_role_sd(text, text, text);

create or replace function acm_tools.revoke_role_sd (
  p_schema_name text,
  p_role text,
  p_srv_user text)
returns text
as
$func$
declare
  v_sql text;
  v_role_name text; 
  v_cnt int;
begin
   if not acm_tools.check_stack('acm_tools.revoke_role')
     then
     raise exception 'you are not allowed to manage roles in schema %', p_schema_name;
  end if;
  v_role_name:=case lower(p_role)
                  when 'read_write' then p_schema_name||'_read_write'
                  when 'read_only' then p_schema_name||'_read_only'
                  when 'schema_owner' then p_schema_name||'_owner'
                end;
  v_sql:=$$ revoke $$||v_role_name||$$ from $$||p_srv_user;
  execute v_sql;
  return v_sql;
end;
$func$
language plpgsql security definer;

revoke execute on function acm_tools.revoke_role_sd from public;
