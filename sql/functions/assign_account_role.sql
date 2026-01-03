create or replace function acm_tools.assign_account_role(p_account_name text,
p_acct_user text,
p_acct_user_password text default null)
RETURNS text
AS
$func$
DECLARE
v_sql text;
v_cnt int;
BEGIN
  select count(*) into v_cnt from acm_tools.account_role where account_role_name=p_account_name||'_owner';
  if v_cnt=0 then
     raise exception 'Account % does not exist', p_account_name;
  end if;
  select count(*) into v_cnt from pg_authid where rolname=p_acct_user;
  if v_cnt=0 then
    if p_acct_user_password is null then
       raise exception 'NULL password for new user: %', p_acct_user;
    else
    v_sql:=$$create user $$||p_acct_user||  $$ password $$|| quote_literal(p_acct_user_password)||$$;$$;
    end if;
  else if p_acct_user_password is not null then
        v_sql:=$$alter user $$||p_acct_user||  $$ password $$|| quote_literal(p_acct_user_password)||$$;$$;

        else
       v_sql:=' ';
     end if;
  end if;
  v_sql:=v_sql||$$ grant $$||p_account_name||$$_owner to $$||p_acct_user;
  execute v_sql;
  RETURN v_sql;
END;
$func$
language plpgsql security definer;
revoke execute on function acm_tools.assign_account_role from public;
