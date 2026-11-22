const { test } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const { createDatabase } = require("./helpers/database");
const createApp = require("../backend/src/app");
test("Built-in Admin and User roles are the single, editable role list", async (t) => {
  const db = await createDatabase(),
    password = "Fixture-auth-2026!",
    hash = await bcrypt.hash(password, 4),
    ids = {};
  for (const [username, role, rights] of [
    ["root", "superadmin", {}],
    ["manager", "admin", {}],
    ["member", "user", {}],
    ["custom", "user", { "customers.view": true }],
  ])
    ids[username] = (
      await db.pg.query(
        "INSERT INTO users(username,email,name,role,status,password_hash,rights) VALUES($1,$1||'@example.test',initcap($1),$2,'approved',$3,$4) RETURNING id",
        [username, role, hash, rights],
      )
    ).rows[0].id;
  const server = createApp({ db, sessionSecret: "built-in-roles-test-secret-".repeat(2), origins: [] }).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  t.after(async () => {
    await new Promise((r) => server.close(r));
    await db.pg.close();
  });
  const base = "http://127.0.0.1:" + server.address().port,
    cookies = {};
  async function req(who, method, path, body) {
    const r = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json", cookie: cookies[who] || "" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (r.headers.get("set-cookie")) cookies[who] = r.headers.get("set-cookie").split(";")[0];
    return { status: r.status, body: await r.json() };
  }
  const account = async (who) => (await db.pg.query("SELECT u.role,u.rights,p.name role_name,p.built_in FROM users u LEFT JOIN permission_role p ON p.id=u.permission_role_id WHERE u.id=$1", [ids[who]])).rows[0];
  for (const who of ["root", "manager", "member"])
    assert.equal((await req(who, "POST", "/api/auth/login", { identifier: who, password })).status, 200);

  // One list: Superadmin (fixed) + built-in Admin and User first, then custom roles.
  assert.deepEqual((await req("root", "GET", "/api/admin/system-roles")).body.data.map((r) => r.name), ["Superadmin"]);
  const roles = (await req("root", "GET", "/api/admin/roles?status=all")).body.data;
  assert.deepEqual(roles.slice(0, 2).map((r) => [r.name, r.built_in]), [["Admin", "admin"], ["User", "user"]]);
  assert.equal(roles.filter((r) => ["admin", "user"].includes(r.name.toLowerCase())).length, 2);
  const adminRole = roles.find((r) => r.built_in === "admin"),
    userRole = roles.find((r) => r.built_in === "user");

  // Accounts without explicit permissions follow their built-in role; custom permissions stay custom.
  assert.equal((await account("manager")).role_name, "Admin");
  assert.equal((await account("member")).role_name, "User");
  assert.equal((await account("custom")).role_name, null);
  assert.equal((await account("custom")).rights["customers.view"], true);

  // Built-in roles cannot be renamed, deactivated or duplicated by name.
  assert.equal((await req("root", "PUT", "/api/admin/roles/" + userRole.id, { name: "Members" })).status, 400);
  assert.equal((await req("root", "PUT", "/api/admin/roles/" + userRole.id, { status: "inactive" })).status, 400);
  assert.equal((await req("root", "POST", "/api/admin/roles", { name: "admin" })).status, 400);

  // Editing the built-in User role changes every User that follows it.
  assert.equal((await req("member", "GET", "/api/customers")).status, 403);
  assert.equal((await req("root", "PUT", "/api/admin/roles/" + userRole.id, { description: "Everyone", rights: { "customers.view": true } })).status, 200);
  assert.equal((await req("member", "GET", "/api/customers")).status, 200);
  assert.equal((await account("custom")).role_name, null);

  // Built-in roles only fit their account type; custom roles stay for Users.
  assert.equal((await req("root", "PUT", `/api/admin/users/${ids.member}/permission-role`, { permission_role_id: adminRole.id })).status, 400);
  const staff = roles.find((r) => r.name === "Staff");
  assert.equal((await req("root", "PUT", `/api/admin/users/${ids.manager}/permission-role`, { permission_role_id: staff.id })).status, 403);

  // Changing the account type moves the account to the new built-in role.
  await db.pg.query("UPDATE users SET role='admin' WHERE id=$1", [ids.member]);
  const promoted = await account("member");
  assert.equal(promoted.role_name, "Admin");
  assert.equal(Object.values(promoted.rights).filter(Boolean).length, Object.values(adminRole.rights).filter(Boolean).length);
});
