CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE FUNCTION public.cleanup_expired_oauth_data() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM oauth_sessions WHERE expires_at < NOW();
    DELETE FROM oauth_auth_codes WHERE expires_at < NOW();
    DELETE FROM oauth_refresh_tokens WHERE expires_at < NOW();
END;
$$;
CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
SET default_tablespace = '';
SET default_table_access_method = heap;
CREATE TABLE public.automations (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    trigger jsonb NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb,
    actions jsonb NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.automations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.automations_id_seq OWNED BY public.automations.id;
CREATE TABLE public.device_states (
    device_id integer NOT NULL,
    state jsonb NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.devices (
    id integer NOT NULL,
    user_id integer NOT NULL,
    device_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(100) NOT NULL,
    traits jsonb NOT NULL,
    attributes jsonb DEFAULT '{}'::jsonb,
    nicknames jsonb DEFAULT '[]'::jsonb,
    room_hint character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.devices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.devices_id_seq OWNED BY public.devices.id;
CREATE TABLE public.oauth_access_tokens (
    token text NOT NULL,
    user_id uuid NOT NULL,
    client_id text NOT NULL,
    scope text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.oauth_auth_codes (
    code character varying(100) NOT NULL,
    user_id integer NOT NULL,
    client_id character varying(255) NOT NULL,
    redirect_uri text NOT NULL,
    scope text,
    expires_at timestamp without time zone NOT NULL
);
CREATE TABLE public.oauth_clients (
    client_id text NOT NULL,
    client_secret text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.oauth_refresh_tokens (
    token character varying(100) NOT NULL,
    user_id integer NOT NULL,
    client_id character varying(255) NOT NULL,
    scope text,
    expires_at timestamp without time zone NOT NULL
);
CREATE TABLE public.oauth_sessions (
    session_id character varying(100) NOT NULL,
    client_id character varying(255) NOT NULL,
    redirect_uri text NOT NULL,
    state character varying(255) NOT NULL,
    scope text,
    expires_at timestamp without time zone NOT NULL
);
CREATE TABLE public.oauth_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    access_token character varying(500) NOT NULL,
    refresh_token character varying(500),
    token_type character varying(50) DEFAULT 'Bearer'::character varying,
    expires_at timestamp without time zone,
    scope character varying(500),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.oauth_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.oauth_tokens_id_seq OWNED BY public.oauth_tokens.id;
CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    agent_user_id character varying(100) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_login timestamp without time zone
);
CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
ALTER TABLE ONLY public.automations ALTER COLUMN id SET DEFAULT nextval('public.automations_id_seq'::regclass);
ALTER TABLE ONLY public.devices ALTER COLUMN id SET DEFAULT nextval('public.devices_id_seq'::regclass);
ALTER TABLE ONLY public.oauth_tokens ALTER COLUMN id SET DEFAULT nextval('public.oauth_tokens_id_seq'::regclass);
ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
ALTER TABLE ONLY public.automations
    ADD CONSTRAINT automations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.device_states
    ADD CONSTRAINT device_states_pkey PRIMARY KEY (device_id);
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_device_id_key UNIQUE (user_id, device_id);
ALTER TABLE ONLY public.oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_pkey PRIMARY KEY (token);
ALTER TABLE ONLY public.oauth_auth_codes
    ADD CONSTRAINT oauth_auth_codes_pkey PRIMARY KEY (code);
ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (client_id);
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (token);
ALTER TABLE ONLY public.oauth_sessions
    ADD CONSTRAINT oauth_sessions_pkey PRIMARY KEY (session_id);
ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_agent_user_id_key UNIQUE (agent_user_id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
CREATE INDEX idx_agent_user_id ON public.users USING btree (agent_user_id);
CREATE INDEX idx_auth_codes_expires ON public.oauth_auth_codes USING btree (expires_at);
CREATE INDEX idx_device_id ON public.devices USING btree (device_id);
CREATE INDEX idx_email ON public.users USING btree (email);
CREATE INDEX idx_enabled ON public.automations USING btree (enabled);
CREATE INDEX idx_oauth_access_tokens_expires_at ON public.oauth_access_tokens USING btree (expires_at);
CREATE INDEX idx_oauth_sessions_expires ON public.oauth_sessions USING btree (expires_at);
CREATE INDEX idx_oauth_tokens_user_id ON public.oauth_tokens USING btree (user_id);
CREATE INDEX idx_refresh_tokens_expires ON public.oauth_refresh_tokens USING btree (expires_at);
CREATE INDEX idx_user_automations ON public.automations USING btree (user_id);
CREATE INDEX idx_user_codes ON public.oauth_auth_codes USING btree (user_id);
CREATE INDEX idx_user_devices ON public.devices USING btree (user_id);
CREATE INDEX idx_user_tokens ON public.oauth_refresh_tokens USING btree (user_id);
ALTER TABLE ONLY public.automations
    ADD CONSTRAINT automations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_states
    ADD CONSTRAINT device_states_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.oauth_auth_codes
    ADD CONSTRAINT oauth_auth_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;