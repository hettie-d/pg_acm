create or replace function acm_tools.assign_role(p_role_name text,
p_user text,
p_password text default null)

RETURNS text
AS
$func$
DECLARE
v_sql text;
v_cnt int;
BEGIN
   select count(*) into v_cnt from acm_tools.allowed_role where role_name=p_role_name;
    if v_cnt=0 then
       raise exception 'Role % is not allowed', p_role_name;
  end if;
  select count(*) into v_cnt from pg_authid where rolname=p_srv_user;
  if v_cnt=0 then
    if p_password is null then
       raise exception 'NULL password for new user: %', p_srv_user;
    else
    v_sql:=$$create user $$||p_user||  $$ password $$|| quote_literal(p_password)||$$;$$;
    end if;
  else if p_password is not null then
        v_sql:=$$alter user $$||p_user||  $$ password $$|| quote_literal(p_password)||$$;$$;

        else
       v_sql:=' ';
     end if;
  end if;
  v_sql:=v_sql||$$ grant $$||p_role_name||$$ to $$||p_srv_user;
  execute v_sql;
  RETURN v_sql;
END;
$func$
language plpgsql security definer;
revoke execute on function acm_tools.assign_role from public;

