create or replace function acm_tools.list_account_schemas(p_account_name text)
returns setof text language sql
as
$$
  with recursive x as
 
   (
     select member::regrole,
            roleid::regrole as role
      from pg_auth_members as m
      union all
     select x.member::regrole,
            m.roleid::regrole
      from pg_auth_members as m
      join x on m.member = x.role
     )
     select nspname 
     from x
	 join pg_namespace s
	  on x.role=nspowner::regrole
     where
        member::text = p_account_name||'_owner'  
          
;
$$;
revoke execute on function acm_tools.list_account_schemas from public;