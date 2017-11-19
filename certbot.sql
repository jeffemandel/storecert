CREATE TABLE public.certstore
	(cert text ,
    chain text ,
    fullchain text ,
    privkey text ,
    server text unique,
    CONSTRAINT server_key PRIMARY KEY (server)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.certstore
    OWNER to postgres;

GRANT INSERT, SELECT, UPDATE, DELETE ON TABLE public.certstore TO certbot;

GRANT SELECT ON TABLE public.certstore TO certuser;

GRANT ALL ON TABLE public.certstore TO postgres;    
