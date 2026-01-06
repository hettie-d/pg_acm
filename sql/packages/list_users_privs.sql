drop type if exists acm_tools.users cascade;
create type acm_tools.users as (
user_name text,
max_connections integer
);

drop type if exists acm_tools.schema_roles_record cascade;
create type acm_tools.schema_roles_record as(
schema_name text,
schema_owner text,
owner_users acm_tools.users[],
read_only_role text,
read_users acm_tools.users[],
read_write_role text,
app_users acm_tools.users[]
);

--select * from acm_tools.list_schemas_roles_flat ()
create or replace function acm_tools.list_schemas_roles_flat ()
returns setof acm_tools.schema_roles_record
language plpgsql
as
$body$
begin
return query select
s.nspname::text as schema_name,
r.rolname::text as schema_owner,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= r.rolname
  and pr.rolcanlogin is true
  ) as owner_users,
case (nspacl @> (s.nspname||'_read_only=u/'||r.rolname)::aclitem )
when true then s.nspname||'_read_only'
else 'no read-only role'
end as read_only_role,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= s.nspname||'_read_only'
  and pr.rolcanlogin is true
  ) as read_users,
case (nspacl @> (s.nspname||'_read_write=u/'||r.rolname)::aclitem )
when true then s.nspname||'_read_write'
else 'no read-write role'
end as read_write_role,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= s.nspname||'_read_write'
  and pr.rolcanlogin is true
  ) as write_users
from pg_namespace s
join pg_roles r
on r.oid=s.nspowner
where nspacl is not null
and  nspname not in ('pg_catalog', 'information_schema', 'acm_tools', 'public')
order by nspname;
end;
$body$;

--select to_json(acm_tools.list_schemas_roles ())
create or replace function acm_tools.list_schemas_roles ()
returns  acm_tools.schema_roles_record[]
language plpgsql
as
$body$
declare
v_sql text;
v_result acm_tools.schema_roles_record[];
begin
v_sql:= $$select array_agg(
row(s.nspname::text ,
r.rolname::text ,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= r.rolname
  and pr.rolcanlogin is true
  ) ,
case (nspacl @> (s.nspname||'_read_only=u/'||r.rolname)::aclitem )
when true then s.nspname||'_read_only'
else 'no read-only role'
end ,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= s.nspname||'_read_only'
  and pr.rolcanlogin is true
  ) ,
case (nspacl @> (s.nspname||'_read_write=u/'||r.rolname)::aclitem )
when true then s.nspname||'_read_write'
else 'no read-write role'
end,
(with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  from x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  where  x.role::text= s.nspname||'_read_write'
  and pr.rolcanlogin is true
  ))::acm_tools.schema_roles_record)
from pg_namespace s
join pg_roles r
on r.oid=s.nspowner
where nspacl is not null
and  nspname not in ('pg_catalog', 'information_schema', 'acm_tools', 'public')
$$;
execute v_sql into v_result;
return  v_result;
end;
$body$;

drop type if exists acm_tools.db_privs_record cascade;
create type acm_tools.db_privs_record as (
   priv_type text,
   object_name text,
   role_user_name name,
   schema_default_priv text,
   permission text
);

create or replace function acm_tools.db_direct_privs_select ()
returns setof acm_tools.db_privs_record
language plpgsql
as
$body$
begin
return query
select 'schema priv' ,
a.* from
(select
      nspname::text,
      rolname,
      object_type,
      string[3]::text
  from (
        select
           nspname,
           object_type,
           (string_to_array(rtrim(ltrim(aclexplode(nspacl)::text,'('),')'),',')) as string
        from  (select
                  nspname,
                 'schema' as object_type,
                  nspacl
               from pg_namespace
               where nspname not like 'pg_%'
                     and nspname not in ('public', 'information_schema')
               union
               select
                  nspname,
                  case(defaclobjtype)
                     when 'S' then 'sequence'
                     when 'r' then 'table'
                  end,
                  d.defaclacl
               from pg_default_acl d
               join pg_namespace s on s.oid=defaclnamespace
               where nspname not like 'pg_%'
                     and nspname not in ('public', 'information_schema')

                 )s
        where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')
        ) b
  join pg_roles r on r.oid=b.string[2]::oid
  where rolname !='postgres'
)a
union all
 select 'table priv' ,
 a.* from
(select nspname||'.'||relname::text,
rolname,
'n/a',
string[3]::text
from (
select relname,
nspname,
(string_to_array(rtrim(ltrim(aclexplode(relacl)::text,'('),')'),',')) as string
from
pg_class p
join pg_namespace s
on s.oid=p.relnamespace
where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')
and relkind in ('r','S','v','m')
) b
join pg_roles r on r.oid=b.string[2]::oid
where rolname !='postgres'
)a
;
end ;$body$;

create or replace function acm_tools.db_all_privs_select ()
returns setof acm_tools.db_privs_record
language plpgsql
as
$body$
begin
return query
select 'schema priv' ,
a.* from
(select nspname::text,
rolname,
object_type,
string[3]::text
from (
select nspname,
object_type,
(string_to_array(rtrim(ltrim(aclexplode(nspacl)::text,'('),')'),',')) as string
from  (select nspname,
  'schema' as object_type,
  nspacl from pg_namespace
   where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')
 union
 select nspname,
  case(defaclobjtype)
    when 'S' then 'sequence'
      when 'r' then 'table'
      when 'm' then 'mview'
      when 'v' then 'view'
      else 'other'
      end,
  d.defaclacl from pg_default_acl d
    join pg_namespace s on s.oid=defaclnamespace
    where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')

)s
where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')

) b
join pg_roles r on r.oid=b.string[2]::oid
where rolname !='postgres'
)a
union all
 select 'table priv' ,
 a.* from
(select nspname||'.'||relname::text,
rolname,
'n/a',
string[3]::text
from (
select relname,
nspname,
(string_to_array(rtrim(ltrim(aclexplode(relacl)::text,'('),')'),',')) as string
from
pg_class p
join pg_namespace s
on s.oid=p.relnamespace
where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')
and relkind in ('r','S','v','m')
) b
join pg_roles r on r.oid=b.string[2]::oid
where rolname !='postgres'
)a
union all
 select 'table priv inherit' ,
 a.* from
(select nspname||'.'||relname::text,
member::text,
'n/a',
string[3]::text
from (
select relname,
nspname,
(string_to_array(rtrim(ltrim(aclexplode(relacl)::text,'('),')'),',')) as string
from
pg_class p
join pg_namespace s
on s.oid=p.relnamespace
where nspname not like 'pg_%' and nspname not in ('public', 'information_schema')
and relkind in ('r','S','v','m')
) b
join pg_roles r on r.oid=b.string[2]::oid
join (with recursive x as
(
  select member::regrole,
         roleid::regrole as role,
       roleid,
         member::regrole || ' -> ' || roleid::regrole as path
  from pg_auth_members as m
  union all
  select x.member::regrole,
         m.roleid::regrole,
       m.roleid,
         x.path || ' -> ' || m.roleid::regrole
 from pg_auth_members as m
    join x on m.member = x.role
  )
  select member, role, roleid, path
  from x
  where member::text not like 'pg%'
  and member::text!='postgres'
  and member::text not like 'rds%'
  and role::text not like 'pg%'
) ir
on ir.roleid=r.oid
where member::text !='postgres'
)a;
end ;$body$;
