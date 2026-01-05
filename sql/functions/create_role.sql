create or replace function pg_acm.create_role(p_role_name text)

RETURNS text
AS
$func$
DECLARE
v_sql text;
v_cnt int;
BEGIN
   select count(*) into v_cnt from pg_acm.allowed_role where role_name=p_role_name;
    if v_cnt>0 then
       raise exception 'Role % already exists', p_role_name;
    else
       insert into pg_acm.allowed_role (role_name) values (p_role_name);
  end if;
  select count(*) into v_cnt from pg_authid where rolname=p_role_name;
  if v_cnt>0 then
    raise exception 'Role % already exists', p_role_name;
    else
    v_sql:=$$create role $$||p_role_name||$$;$$;
    end if;
   execute v_sql;
  RETURN v_sql;
END;
$func$
language plpgsql security definer;
revoke execute on function pg_acm.create_role(text) from public;
