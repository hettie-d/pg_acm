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

