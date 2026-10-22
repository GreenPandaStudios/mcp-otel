import pg from 'pg';
import { readFile } from 'node:fs/promises';

export class Store {
  constructor(url) { this.pool = new pg.Pool({ connectionString: url, max: 8, connectionTimeoutMillis: 5000, statement_timeout: 10000 }); }
  query(sql, values) { return this.pool.query(sql, values); }
  async migrate() { await this.query(await readFile(new URL('./schema.sql', import.meta.url), 'utf8')); }
  async tx(fn) {
    const c = await this.pool.connect();
    try { await c.query('BEGIN'); const result = await fn(c); await c.query('COMMIT'); return result; }
    catch (error) { await c.query('ROLLBACK'); throw error; } finally { c.release(); }
  }
  close() { return this.pool.end(); }
}
