-- One role list: the built-in Admin and User roles ARE editable permission roles.
-- Superadmin stays fixed (all permissions). Built-in roles cannot be renamed,
-- deactivated or assigned to the other account type; custom roles (e.g. Staff)
-- remain fully editable and apply to User accounts. Accounts follow their
-- built-in role by default; per-account custom permissions remain possible.
ALTER TABLE permission_role ADD COLUMN built_in text CHECK(built_in IN ('admin','user'));
CREATE UNIQUE INDEX permission_role_built_in ON permission_role(built_in) WHERE built_in IS NOT NULL;

-- Adopt the earlier presets as the built-in roles (create them if missing).
UPDATE permission_role SET built_in='admin',name='Admin',status='active',
 description='Built-in role for Admin accounts. Its permissions apply to every Admin that follows it.'
WHERE lower(trim(name))='admin';
UPDATE permission_role SET built_in='user',name='User',status='active',
 description='Built-in role for User accounts. Users without business permissions use the User workspace.'
WHERE lower(trim(name))='user';
INSERT INTO permission_role(name,description,rights,built_in)
SELECT 'Admin','Built-in role for Admin accounts. Its permissions apply to every Admin that follows it.',r,'admin' FROM (SELECT jsonb_object_agg(key,true) r FROM rights) x
WHERE NOT EXISTS(SELECT 1 FROM permission_role WHERE built_in='admin');
INSERT INTO permission_role(name,description,rights,built_in)
SELECT 'User','Built-in role for User accounts. Users without business permissions use the User workspace.',r,'user' FROM (SELECT jsonb_object_agg(key,false) r FROM rights) x
WHERE NOT EXISTS(SELECT 1 FROM permission_role WHERE built_in='user');

-- Reserved names are only allowed on the built-in rows.
ALTER TABLE permission_role DROP CONSTRAINT permission_role_name_check;
ALTER TABLE permission_role ADD CONSTRAINT permission_role_name_check
 CHECK(length(trim(name)) BETWEEN 1 AND 80 AND (built_in IS NOT NULL OR lower(trim(name)) NOT IN ('superadmin','admin','user')));

CREATE OR REPLACE FUNCTION hope_role_user_rights() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE profile permission_role;
BEGIN
 IF NEW.role='superadmin' THEN NEW.permission_role_id:=NULL; RETURN NEW; END IF;
 -- New accounts without explicit permissions, and accounts whose system role
 -- changes, follow the built-in role of their account type.
 IF (TG_OP='INSERT' AND NEW.permission_role_id IS NULL
     AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(NEW.rights) WHERE value='true'))
    OR (TG_OP='UPDATE' AND NEW.role IS DISTINCT FROM OLD.role) THEN
  SELECT id INTO NEW.permission_role_id FROM permission_role WHERE built_in=NEW.role;
 END IF;
 IF NEW.permission_role_id IS NOT NULL THEN
  SELECT * INTO profile FROM permission_role WHERE id=NEW.permission_role_id;
  IF FOUND THEN
   IF profile.built_in IS NOT NULL AND profile.built_in<>NEW.role THEN
    RAISE EXCEPTION 'The built-in % role applies to % accounts only.',profile.name,profile.name USING ERRCODE='23514';
   END IF;
   IF profile.built_in IS NULL AND NEW.role<>'user' THEN
    RAISE EXCEPTION 'Custom roles apply to User accounts only.' USING ERRCODE='42501';
   END IF;
   NEW.rights:=CASE WHEN profile.status='active' THEN profile.rights ELSE '{}'::jsonb END;
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hope_save_permission_role(p_actor uuid,p_id uuid,p_data jsonb,p_expected timestamptz DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE actor users; previous permission_role; saved permission_role; k text; r jsonb;
BEGIN
 SELECT * INTO actor FROM users WHERE id=p_actor AND status='approved' AND NOT is_deleted FOR SHARE;
 IF NOT FOUND OR actor.role NOT IN ('admin','superadmin') THEN RAISE EXCEPTION 'Administrator required' USING ERRCODE='42501'; END IF;
 IF jsonb_typeof(p_data) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Role data must be an object'; END IF;
 FOR k IN SELECT jsonb_object_keys(p_data) LOOP IF k NOT IN ('name','description','rights','status') THEN RAISE EXCEPTION 'Unsupported role field: %',k; END IF; END LOOP;
 PERFORM set_config('app.username',coalesce(actor.username,actor.email,actor.id::text),true);
 IF p_id IS NOT NULL THEN
  SELECT * INTO previous FROM permission_role WHERE id=p_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Role not found' USING ERRCODE='P0002'; END IF;
  IF p_expected IS NOT NULL AND previous.updated_at IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'Role changed elsewhere; reopen it before saving' USING ERRCODE='40001'; END IF;
  IF previous.built_in IS NOT NULL AND (
     (p_data ? 'name' AND trim(p_data->>'name') IS DISTINCT FROM previous.name) OR
     (p_data ? 'status' AND p_data->>'status' IS DISTINCT FROM 'active')) THEN
   RAISE EXCEPTION 'Built-in roles cannot be renamed or made inactive.' USING ERRCODE='23514';
  END IF;
 END IF;
 r:=hope_normalize_rights(coalesce(p_data->'rights',previous.rights,'{}'::jsonb));
 IF p_id IS NULL THEN
  INSERT INTO permission_role(name,description,rights,status) VALUES(trim(p_data->>'name'),coalesce(p_data->>'description',''),r,coalesce(p_data->>'status','active')) RETURNING * INTO saved;
 ELSE
  UPDATE permission_role SET name=coalesce(trim(p_data->>'name'),name),description=coalesce(p_data->>'description',description),rights=r,status=coalesce(p_data->>'status',status),updated_at=clock_timestamp() WHERE id=p_id RETURNING * INTO saved;
  UPDATE users SET rights=CASE WHEN saved.status='active' THEN saved.rights ELSE '{}'::jsonb END WHERE permission_role_id=saved.id AND role IN ('admin','user');
 END IF;
 INSERT INTO audit_log(table_name,action,record_key,old_values,new_values,action_by) VALUES('permission_role',CASE WHEN p_id IS NULL THEN 'ADD' ELSE 'EDIT' END,saved.id::text,CASE WHEN p_id IS NOT NULL THEN to_jsonb(previous) ELSE NULL END,to_jsonb(saved),audit_user());
 RETURN to_jsonb(saved);
END $$;

CREATE OR REPLACE FUNCTION hope_assign_permission_role(p_actor uuid,p_user uuid,p_role uuid,p_expected timestamptz DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE profile permission_role; target users; actor users;
BEGIN
 SELECT * INTO actor FROM users WHERE id=p_actor AND status='approved' AND NOT is_deleted FOR SHARE;
 IF NOT FOUND OR actor.role NOT IN ('admin','superadmin') THEN RAISE EXCEPTION 'Administrator required' USING ERRCODE='42501'; END IF;
 IF p_role IS NOT NULL THEN
  SELECT * INTO profile FROM permission_role WHERE id=p_role FOR SHARE;
  IF NOT FOUND OR profile.status<>'active' THEN RAISE EXCEPTION 'Choose an active permission role'; END IF;
 END IF;
 SELECT * INTO target FROM users WHERE id=p_user FOR UPDATE;
 IF NOT FOUND OR target.is_deleted THEN RAISE EXCEPTION 'User not found' USING ERRCODE='P0002'; END IF;
 IF target.role='superadmin' THEN RAISE EXCEPTION 'Superadmin has fixed full access' USING ERRCODE='42501'; END IF;
 IF target.role='admin' AND actor.role<>'superadmin' THEN RAISE EXCEPTION 'Only a Superadmin can change an Admin''s role' USING ERRCODE='42501'; END IF;
 IF target.role='admin' AND p_role IS NOT NULL AND profile.built_in IS NULL THEN RAISE EXCEPTION 'Named permission roles apply to Users only' USING ERRCODE='42501'; END IF;
 IF profile.built_in IS NOT NULL AND profile.built_in<>target.role THEN
  RAISE EXCEPTION 'The built-in % role applies to % accounts only.',profile.name,profile.name USING ERRCODE='23514';
 END IF;
 IF p_expected IS NOT NULL AND target.updated_at IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'User changed elsewhere; reopen before saving' USING ERRCODE='40001'; END IF;
 RETURN hope_mutate(p_actor,'users','update',jsonb_build_object('id',p_user),jsonb_build_object('permission_role_id',p_role,'rights',CASE WHEN p_role IS NULL THEN '{}'::jsonb ELSE profile.rights END));
END $$;

-- Re-registration of a disapproved email returns the account to the built-in User role.
CREATE OR REPLACE FUNCTION hope_confirm_registration(p_id uuid,p_code text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE c registration_challenge; u users;
BEGIN
 SELECT * INTO c FROM registration_challenge WHERE id=p_id FOR UPDATE;
 IF NOT FOUND OR c.used_at IS NOT NULL OR c.expires_at<=now() OR c.attempts>=5 THEN RETURN NULL; END IF;
 UPDATE registration_challenge SET attempts=attempts+1 WHERE id=p_id;
 IF c.code_hash<>p_code THEN RETURN NULL; END IF;
 SELECT * INTO u FROM users WHERE lower(email)=c.email FOR UPDATE;
 IF FOUND THEN
  IF u.status<>'disapproved' OR u.is_deleted THEN RAISE EXCEPTION 'Email or username already exists.' USING ERRCODE='23505'; END IF;
  UPDATE users SET name=c.name,username=c.username,password_hash=c.password_hash,role='user',status='pending',
   permission_role_id=(SELECT id FROM permission_role WHERE built_in='user'),rights='{}',reset_token=NULL,reset_token_expires=NULL
  WHERE id=u.id RETURNING * INTO u;
  UPDATE user_token SET used_at=now() WHERE user_id=u.id AND used_at IS NULL;
 ELSE
  INSERT INTO users(email,name,username,password_hash,role,status) VALUES(c.email,c.name,c.username,c.password_hash,'user','pending') RETURNING * INTO u;
 END IF;
 UPDATE registration_challenge SET used_at=now(),password_hash=NULL,code_hash=NULL WHERE id=p_id;
 RETURN jsonb_build_object('id',u.id,'email',u.email,'name',u.name,'username',u.username,'role',u.role,'status',u.status);
END $$;

-- Existing accounts: anyone on the wrong built-in role keeps their permissions as
-- custom permissions; accounts with no permissions at all follow their built-in role.
-- Accounts with custom permissions or a custom role are left unchanged.
UPDATE users u SET permission_role_id=NULL
FROM permission_role p WHERE p.id=u.permission_role_id AND coalesce(p.built_in,'user')<>u.role;
UPDATE users u SET permission_role_id=p.id
FROM permission_role p
WHERE p.built_in=u.role AND u.permission_role_id IS NULL
 AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(u.rights) WHERE value='true');

INSERT INTO app_migration(version) VALUES('202611230023_built_in_roles');
NOTIFY pgrst,'reload schema';
