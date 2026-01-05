drop function if exists pg_acm.assign_schema_role_sd (text, text,text,text);

create or replace function pg_acm.assign_schema_role_sd (p_schema_name text,
p_role text,
p_srv_user text,
p_password text default null,
p_update_search_path boolean default true)
RETURNS text
AS
$func$
DECLARE
v_sql text;
v_cnt int;
v_role_name text;
BEGIN
  if not pg_acm.check_stack('pg_acm.assign_schema_role ')
    and not pg_acm.check_stack('pg_acm.create_schema_roles')
     then
     raise exception 'You are not allowed to assign roles in schema %', p_schema_name;
  end if;
  v_role_name:=case lower(p_role)
                  when 'read_write' then p_schema_name||'_read_write'
                  when 'read_only' then p_schema_name||'_read_only'
                  when 'schema_owner' then p_schema_name||'_owner'
                end;
  select count(*) into v_cnt from pg_authid where rolname=p_srv_user;
  if v_cnt=0 then --new user
    if p_password is null then
       raise exception 'NULL password for new user: %', p_srv_user;
    else
    v_sql:=$$create user $$||p_srv_user||  $$ password $$|| quote_literal(p_password)||$$;$$;
    end if;
  else -- user exists
    if p_password is not null then
        v_sql:=$$alter user $$||p_srv_user||  $$ password $$|| quote_literal(p_password)||$$;$$;
   else
    v_sql:=' ';
  end if;
  end if; --user exists
  v_sql:=v_sql||$$ grant $$||v_role_name||$$ to $$||p_srv_user||$$;$$;
  if p_update_search_path
     then v_sql:=v_sql ||$$ alter user $$||p_srv_user||$$ set search_path to $$||p_schema_name||$$, public;$$;
  end if;
  execute v_sql;
  RETURN v_sql;
END;
$func$
language plpgsql security definer;

revoke execute on function pg_acm.assign_schema_role_sd (text, text,text,text,boolean) from public;
