# acm_tools User Guide

## Functions provided

| Function name | Description | Permissions Needed |
| ------------- | ----------- | ------------------ |
| `acm_tools.perm_create_cust_account(account_name)` | creates a new account | `database owner` |
| `acm_tools.perm_drop_cust_account(account_name)` | drops an account | `database owner` |
| `acm_tools.perm_assign_schema_schema_owner_role(schema_name, schema_owner_name, schema_owner_password)` | assigns schema owner roles to users | `account owner` |
| `acm_tools.perm_revoke_schema_schema_owner_role(schema_name, schema_owner_name)` | revokes schema owner roles from users | `account owner` |
| `acm_tools.perm_assign_account_role(account_name, role_name, role_password)` | assigns account owner roles to users | `account owner` |
| `acm_tools.perm_assign_schema_app_role(schema_name, app_user_name, app_user_password)` | assigns read_write roles to users | `account owner` |
| `acm_tools.perm_revoke_schema_app_role(schema_name, app_user_name)` | revokes read_write roles from users | `account owner` |
| `acm_tools.perm_assign_schema_ro_role(schema_name, ro_user_name, ro_user_password)` | assigns read_only roles to users | `account owner` |
| `acm_tools.perm_revoke_schema_ro_role(schema_name, ro_user_name)` | revokes read_only roles from users | `account owner` |

## How to use

### Create new account

```sql
SELECT * FROM acm_tools.create_cust_account (
  'account1'
);
```

---

### Create a user for an account

```sql
SELECT * FROM acm_tools.assign_account_role(
  p_account_name => 'account1',
  p_acct_user => 'acct_user1',
  p_acct_user_password => 'acct_user_pwd'
);
```

---

### What happens next

A user which is granted an account owner role can create and drop schemas and any objects in the schemas created for this account. When a schema is created, event trigger automatically creates three roles:

* schema_owner (owns the schema and default privileges
* schema_read_write (select, insert, update, delete, truncate privileges for the schema)
* schema_read_only (select privileges for schema)

When the schema is dropped, all associated roles are dropped as well.

Additional functions allow granting these roles to users.

**Note: all functions listed below can be executed either by account owner or by database owner**

### Assign roles to users and create users if they don't exist

In each case, a corresponding function would check whether the user exists, and create it if it doesn't exist, and assign the corresponding privilege and the search_path. If the user already exists, the password is not needed, and will be ignored if provided.

```sql
SELECT * FROM acm_tools.assign_schema_app_role (
  'schema_name',
  'app_user_name',
  'app_user_password'
);

SELECT * FROM acm_tools.assign_schema_schema_owner_role (
  'schema_name',
  'schema_owner_user_name',
  'schema_owner_password'
);

SELECT * FROM acm_tools.assign_schema_ro_role (
  'schema_name',
  'ro_user_name',
  'ro_user_password'
);
```

For all functions which involve user creation, there is a check so that if you need to create a new user, you must provide the password, otherwise, exception will be thrown.

### Additional functionality

All `assign` functions have an additional boolean parameter p_update_search_path; default is `true`. If it is set to `false`, the user's default search path will not be updated.

#### Example calls

New app user, don't update search path

```sql
SELECT * FROM acm_tools.assign_schema_app_role (
  'schema_name',
  'app_user_name',
  'app_user_password',
  false
);
```

Existing user, update the search path:

```sql
SELECT * FROM acm_tools.assign_schema_ro_role (
  'schema_name',
  'ro_user_name',
  null,
  true
);
```

### Matching “revoke” functions for each user category

```sql
SELECT * FROM acm_tools.revoke_schema_app_role (
  'schema_name',
  'app_user_name'
);

SELECT * FROM acm_tools.revoke_schema_schema_owner_role (
  'schema_name',
  'schema_owner_user_name'
);

SELECT * FROM acm_tools.revoke_schema_ro_role (
  'schema_name',
  'ro_user_name'
);
```

## Additional roles management functions

| Function name | Description | Permissions Needed |
| ------------- | ----------- | ------------------ |
| `acm_tools.create_role('new_role')` | Creates a new role without permissions | `database owner` |
| `acm_tools.assign_role('new_role','new_user','passwd')` | grants previously created role to a new or existing user; leave password null fo existing user | `database owner` |

## Other administrative functions

| Function name | Description | Permissions Needed |
| ------------- | ----------- | ------------------ |
| `acm_tools.terminate_process(pid)` | kills any non-superuser session | `database owner` |
| `acm_tools.db_direct_privs_select()` | lists all directly granted privileges | `database owner` |
| `acm_tools.db_all_privs_select()` | lists all atomic privileges for all db users | `database owner` |
