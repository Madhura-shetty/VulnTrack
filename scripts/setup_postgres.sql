-- Run ONCE as the PostgreSQL superuser (postgres):
--   psql -U postgres -f scripts/setup_postgres.sql
-- Change the password below, and use the same one in .env
CREATE ROLE vulntrack_app LOGIN PASSWORD 'change-me' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE vulntrack_db OWNER vulntrack_app;
