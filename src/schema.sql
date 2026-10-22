CREATE TABLE IF NOT EXISTS principals (
 id text PRIMARY KEY, name text NOT NULL, active boolean NOT NULL DEFAULT true,
 scopes text[] NOT NULL, namespaces text[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS oauth_clients (
 id text PRIMARY KEY, secret_hash text NOT NULL, principal_id text NOT NULL REFERENCES principals(id),
 redirects text[] NOT NULL, active boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS browser_sessions (
 id_hash text PRIMARY KEY, csrf_hash text NOT NULL, principal_id text REFERENCES principals(id),
 grant_id text, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
 code_hash text PRIMARY KEY, client_id text NOT NULL REFERENCES oauth_clients(id),
 session_hash text NOT NULL REFERENCES browser_sessions(id_hash), redirect_uri text NOT NULL,
 challenge text NOT NULL, scopes text[] NOT NULL, resource text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
 id text PRIMARY KEY, principal_id text NOT NULL REFERENCES principals(id), client_id text NOT NULL REFERENCES oauth_clients(id),
 scopes text[] NOT NULL, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
 token_hash text PRIMARY KEY, grant_id text NOT NULL REFERENCES grants(id), kind text NOT NULL,
 expires_at timestamptz NOT NULL, consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS subscriptions (
 id text PRIMARY KEY, principal_id text NOT NULL REFERENCES principals(id), grant_id text NOT NULL REFERENCES grants(id),
 name text NOT NULL, arguments jsonb NOT NULL, url text NOT NULL, encrypted_secret text NOT NULL,
 old_secret text, rotate_until timestamptz, expires_at timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS events (
 seq bigserial PRIMARY KEY, id text UNIQUE NOT NULL, name text NOT NULL,
 namespace text NOT NULL, service text NOT NULL, payload jsonb NOT NULL, dedupe_key text UNIQUE NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS deliveries (
 subscription_id text NOT NULL REFERENCES subscriptions(id), event_seq bigint NOT NULL REFERENCES events(seq),
 status text NOT NULL DEFAULT 'pending', attempts integer NOT NULL DEFAULT 0,
 next_attempt timestamptz NOT NULL DEFAULT now(), lease_until timestamptz, last_status integer,
 PRIMARY KEY(subscription_id,event_seq)
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(next_attempt) WHERE status='pending';
CREATE TABLE IF NOT EXISTS incidents (
 id text PRIMARY KEY, source text NOT NULL, namespace text NOT NULL, service text NOT NULL,
 status text NOT NULL, severity text NOT NULL, summary text NOT NULL,
 evidence jsonb NOT NULL DEFAULT '{}', fingerprint text UNIQUE NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS repairs (
 id text PRIMARY KEY, principal_id text NOT NULL REFERENCES principals(id), incident_id text NOT NULL REFERENCES incidents(id),
 status text NOT NULL, snapshot jsonb, version_hash text, approval_hash text,
 approved_session text, approved_at timestamptz, expires_at timestamptz,
 result jsonb, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit (
 seq bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), principal_id text,
 action text NOT NULL, subject text NOT NULL, detail jsonb NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_repair ON repairs(principal_id,incident_id)
 WHERE status IN ('preparing','ready','approved','deploying');
