create table IF NOT EXISTS tbl_mstr_user
(
    user_id        bigint  not null
        constraint tbl_mstr_user_pkey
            primary key,
    username       varchar not null,
    email          varchar not null,
    firstname      varchar not null,
    lastname       varchar not null,
    phonenumber    varchar not null,
    password       varchar not null,
    created_by     varchar,
    created_date   timestamp,
    updated_by     varchar,
    updated_date   timestamp,
    token_hash     varchar,
    email_verified boolean,
    image_file     varchar
);

alter table tbl_mstr_user
    owner to sadhelx_usr;


create table IF NOT EXISTS tbl_trx_activity
(
    activity_id       varchar not null
        constraint tbl_trx_activity_pkey
            primary key,
    activity_name     varchar not null,
    activity_session  varchar not null,
    activity_time     time    not null,
    activity_username varchar not null
);

alter table tbl_trx_activity
    owner to sadhelx_usr;

create table IF NOT EXISTS tbl_trx_verification_email
(
    id         serial    not null
        constraint tbl_trx_verification_email_pkey
            primary key,
    email      varchar   not null,
    code       varchar   not null,
    type       integer   not null,
    expires_at timestamp not null
);

alter table tbl_trx_verification_email
    owner to sadhelx_usr;

