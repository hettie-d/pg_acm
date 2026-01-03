create or replace function acm_tools.fix_owner_grants()
  returns event_trigger
  language 'plpgsql' security definer
  as $body$
declare
  v_obj record;
  v_roles record;
  v_sql text;
  v_cond text;
  v_schema_owner text;
  v_select boolean;
  v_insert boolean;
  v_update boolean;
  v_delete boolean;
  v_truncate boolean;
begin
  for v_obj in select * from pg_event_trigger_ddl_commands () order by object_type desc loop
    select nspowner::regrole into v_schema_owner
      from pg_namespace where nspname=v_obj.schema_name;
    if upper(v_obj.object_type)!='INDEX' and v_schema_owner is not null and v_obj.schema_name not in ('pg_catalog','information_schema')
    then
      v_sql:=$$alter $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ owner to $$||v_schema_owner;
      case
        when upper(v_obj.object_type) ='TABLE' then
          v_sql:=v_sql ||$$;
          grant select on $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ to $$||v_obj.schema_name||$$_read_only;
          grant select,insert,update,delete, truncate on $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ to $$||v_obj.schema_name||$$_read_write;
          $$;
          for v_roles in (select role_name from acm_tools.allowed_role
                          where role_name similar to  v_obj.schema_name||'_s?i?u?d?t?' escape '') loop
            v_cond :='grant ';
            if v_roles.role_name like v_obj.schema_name||'_s%' then
              v_cond:=v_cond||' select,';
            end if;
            if v_roles.role_name like v_obj.schema_name||'_%i%' then
              v_cond:=v_cond||' insert,';
            end if;
            if v_roles.role_name like v_obj.schema_name||'_%u%' then
              v_cond:=v_cond||' update,';
            end if;
            if v_roles.role_name like v_obj.schema_name||'_%d%' then
              v_cond:=v_cond||' delete,';
            end if;
            if v_roles.role_name like v_obj.schema_name||'_%t%' then
              v_cond:=v_cond||' truncate,';
            end if;
            v_cond:=substr(v_cond,1, length(v_cond)-1);
            v_sql:=v_sql ||$$;$$||v_cond || $$ on $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ to $$||v_roles.role_name;
          end loop;
        when upper(v_obj.object_type) in ('VIEW', 'MATERIALIZED VIEW') then
          v_sql :=v_sql ||$$;
            grant select on table $$||v_obj.object_identity||$$ to $$||v_obj.schema_name||$$_read_only;
            grant select on table $$||v_obj.object_identity||$$ to $$||v_obj.schema_name||$$_read_write;
            $$;
          for v_roles in (select role_name from acm_tools.allowed_role
                          where role_name similar to  v_obj.schema_name||'_s?i?u?d?t?' escape '') loop
            if v_roles.role_name like v_obj.schema_name||'_s%' then
              v_sql:=v_sql ||$$;
              grant select on table $$||v_obj.object_identity||$$ to $$||v_roles.role_name;
            end if;
          end loop;
        when upper(v_obj.object_type) ='SEQUENCE'  then
          v_sql:=v_sql ||$$;
          grant usage on $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ to $$||v_obj.schema_name||$$_read_write;
          $$;
          for v_roles in (select role_name from acm_tools.allowed_role
                          where role_name similar to  v_obj.schema_name||'_s?i?u?d?t?' escape '') loop
            if v_roles.role_name like v_obj.schema_name||'_%i%' then
              v_sql:=v_sql ||$$;
              grant usage on $$||v_obj.object_type||$$ $$||v_obj.object_identity||$$ to $$||v_roles.role_name;
            end if;
          end loop;
        else null;
      end case;
      execute v_sql;
    end if;
  end loop;
end;
$body$;

create or replace function acm_tools.create_roles_for_schema()
  returns event_trigger
  language 'plpgsql'
as $body$
declare
  v_obj record;
  v_sql text;
  v_schema_owner text;
  v_current_user text;
  v_schema_name text;
  v_cnt int;
  v_result text;
begin
  v_current_user := current_user;
  if exists (select 1 from  pg_event_trigger
           where evtname='fix_owner_grants' and evtenabled='O')
  then  
    if  v_current_user='postgres'
    then
      raise exception 'need to be a database owner/account owner to create schemas';
    else 
      for v_obj in select * from pg_event_trigger_ddl_commands () order by object_type desc loop
        v_schema_name:= v_obj.object_identity;
      end loop;
      select acm_tools.create_schema(v_schema_name) into v_result;
     end if;
  end if;  
end;
$body$;

create or replace function acm_tools.drop_roles_for_schema()
  returns event_trigger
  language 'plpgsql'
as $body$
declare
  v_obj record;
  v_sql text;
  v_schema_owner text;
  v_current_user text;
  v_schema_name text;
  v_cnt int;
  v_result text;
begin
  v_current_user := current_user;
  if exists (select 1 from  pg_event_trigger
             where evtname='fix_owner_grants' and evtenabled='O')
  then 
    if v_current_user='postgres'
    then
      raise exception 'need to be a schema owner to drop a schema';
    else
      select object_identity into v_schema_name
      from pg_event_trigger_dropped_objects()
      where object_type='schema';
      select acm_tools.drop_schema_roles_sd(v_schema_name) into v_result;
    end if;
  end if;  
end;
$body$;
