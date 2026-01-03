create or replace function acm_tools.drop_schema_roles_sd(
  p_schema_name text)
    returns text
    language 'plpgsql' security definer
as $body$
declare
v_sql text;
v_roles_sql text;
v_schema_owner text=p_schema_name||'_owner';
v_read_only_role text:=p_schema_name||'_read_only';
v_read_write_role text:=p_schema_name||'_read_write';
begin
  if not acm_tools.check_stack('acm_tools.drop_roles_for_schema')
  then
  raise exception 'you are not allowed to drop schema %', p_schema_name;
end if;
v_roles_sql :=format( $sql$ select array_to_string(array_agg($$revoke $$|| roleid::regrole ||
  $$  from $$||member::regrole), ';')
    from pg_auth_members as m
  where member::text not like 'pg_%%'
  and member::text!='postgres'
  and (roleid::regrole)::text in (%L, %L, %L)$sql$,
v_schema_owner,
v_read_only_role,
v_read_write_role);
--raise notice '%', v_roles_sql;
execute v_roles_sql into v_sql;
v_sql:=
  coalesce(v_sql, ' ')||
  format($sql$;
    drop role %s;
    drop role %s;
    drop role %s;
    $sql$,
    v_read_only_role,
    v_read_write_role,
    v_schema_owner
  );
--raise notice '%', v_sql;
execute v_sql;

return v_sql;
end;
$body$;

revoke execute on function acm_tools.drop_schema_roles_sd(text) from public;

