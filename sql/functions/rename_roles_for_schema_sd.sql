create or replace function acm_tools.rename_roles_for_schema_sd (
   p_old_schema_name text,
   p_new_schema_name text)
returns text
language plpgsql security definer
as $func$
declare
  v_role record;
  v_result text:=' ';
begin
	for v_role in (select rolname from pg_roles
	                 where rolname in (p_old_schema_name||'_read_only',
	                                   p_old_schema_name||'_read_write',
	                                   p_old_schema_name||'_owner')
	                    or rolname similar to  p_old_schema_name||'[_]s?i?u?d?t?' escape '') loop
	             v_result:=v_result||$$alter role $$||v_role.rolname||$$ rename to $$||p_new_schema_name||substr(v_role.rolname, length(p_old_schema_name)+1 )||$$;$$ ;
	end loop;
	raise notice '%', v_result;
	execute v_result;
	return v_result;
end;
$func$;
