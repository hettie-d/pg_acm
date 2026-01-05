create or replace function acm_tools.check_schema_perm(p_schema_name text)
returns boolean language sql
as
$$
select
  exists (
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
    select 1
      from x
      where (
        member::text = current_user
        and role = (select nspowner::regrole from pg_namespace
                      where nspname=p_schema_name)
        or current_user = (select (nspowner::regrole)::text from pg_namespace
                             where nspname = p_schema_name)
      )
);
$$;

revoke execute on function acm_tools.check_schema_perm from public;
