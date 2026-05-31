import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { env } from '../config/env';

async function runMigrations() {
  // Migrations are DDL, so they need the admin role. The least-privilege
  // app role (used by the running API via env.DATABASE_URL) has no DDL
  // grant. MIGRATION_DATABASE_URL lets the deploy hook point this step at
  // the admin connection without changing how the daemon connects. Falls
  // back to DATABASE_URL for local/dev where one role does everything.
  const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? env.DATABASE_URL;
  const client = postgres(migrationUrl, { max: 1 });
  const db = drizzle(client);

  console.log('Running migrations...');
  await migrate(db, { migrationsFolder: './drizzle' });
  console.log('Migrations complete!');

  await client.end();
  process.exit(0);
}

runMigrations().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
