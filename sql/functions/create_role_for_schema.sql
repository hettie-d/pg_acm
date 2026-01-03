create or replace function acm_tools.create_role_for_schema(
  p_schema_name text,
  p_select boolean default false,
  p_insert boolean default false,
  p_update boolean default false,
  p_delete boolean default false,
  p_truncate boolean default false)

RETURNS text
AS
  $func$
DECLARE
  v_sql_grant text;
  v_sql_default text;
  v_sql text;
  v_schema_owner text;
  v_cnt int;
  v_role_name text;
BEGIN
  v_schema_owner:=(select nspowner::regrole from pg_namespace where nspname=p_schema_name);
  v_role_name:=p_schema_name||'_';
  v_sql_default:=$$alter default privileges in schema $$||p_schema_name||$$ for role $$||v_schema_owner||$$ grant $$;
  v_sql_grant:=$$grant $$;

  if    not p_select
    and not p_insert
    and not p_update
    and not p_delete
    and not p_truncate
  then
    raise exception $$Cannot create role %, no permissions specified$$, v_role_name;
  end if;

  if    p_select
    and not p_insert
    and not p_update
    and not p_delete
    and not p_truncate
  then
    raise exception $$Read-only role for this schema already exists, please use role %$$, v_role_name||'read_only';
  end if;

  if    p_select
    and p_insert
    and p_update
    and p_delete
    and p_truncate
  then
    raise exception $$Read-write role for this schema already exists, please use role %$$, v_role_name||'read_write';
  end if;

  if p_select then
    v_role_name:=v_role_name||'s';
    v_sql_default:=v_sql_default||$$ select,$$;
    v_sql_grant:=v_sql_grant||$$ select,$$;
  end if;
  if p_insert then
    v_role_name:=v_role_name||'i';
    v_sql_default:=v_sql_default||$$ insert,$$;
    v_sql_grant:=v_sql_grant||$$ insert,$$;
  end if;
  if p_update then
    v_role_name:=v_role_name||'u';
    v_sql_default:=v_sql_default||$$ update,$$;
    v_sql_grant:=v_sql_grant||$$ update,$$;
  end if;
  if p_delete then
    v_role_name:=v_role_name||'d';
    v_sql_default:=v_sql_default||$$ delete,$$;
    v_sql_grant:=v_sql_grant||$$ delete,$$;
  end if;
  if p_truncate then
    v_role_name:=v_role_name||'t';
    v_sql_default:=v_sql_default||$$ truncate,$$;
    v_sql_grant:=v_sql_grant||$$ truncate,$$;
  end if;

  v_sql_grant:=substr(v_sql_grant,1,length(v_sql_grant)-1);
  v_sql_default:=substr(v_sql_default,1,length(v_sql_default)-1);

  select count(*) into v_cnt from acm_tools.allowed_role where role_name=v_role_name;
  if v_cnt>0 then
    raise exception 'Role % already exists', v_role_name;
  else
    insert into acm_tools.allowed_role (role_name) values (v_role_name);
  end if;

  select count(*) into v_cnt from pg_authid where rolname=v_role_name;
  if v_cnt>0 then
    raise exception 'Role % already exists', v_role_name;
  end if;

  v_sql:=$$create role $$||v_role_name||$$;
  grant usage on schema $$ ||p_schema_name||$$ to $$||v_role_name||$$;$$||
  v_sql_default||$$ on tables to $$||v_role_name||$$;
  $$||
  v_sql_grant ||$$ on all tables in schema $$||p_schema_name||$$ to $$|| v_role_name||$$;$$;

  if p_insert then
    v_sql:=v_sql||$$
    grant usage on all sequences in schema $$||p_schema_name||$$ to $$|| v_role_name||$$;
    alter default privileges in schema $$||p_schema_name||$$ for role $$||v_schema_owner||
    $$ grant usage on  sequences to $$||v_role_name||$$;$$;
    -- raise notice '%', v_sql;
  end if;
  execute v_sql;
  RETURN v_sql;
END;
$func$
language plpgsql security definer;
revoke execute on function acm_tools.create_role_for_schema (text, boolean, boolean, boolean, boolean, boolean) from public;

