PGDMP             	            y            sdx_usermgmt_db    13.1    13.1 
    �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            �           1262    16384    sdx_usermgmt_db    DATABASE     Z   CREATE DATABASE sdx_usermgmt_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'C';
    DROP DATABASE sdx_usermgmt_db;
                sadhelx_usr    false            �            1259    16385    tbl_mstr_user    TABLE     �  CREATE TABLE public.tbl_mstr_user (
    user_id bigint NOT NULL,
    username character varying NOT NULL,
    email character varying NOT NULL,
    firstname character varying NOT NULL,
    lastname character varying NOT NULL,
    phonenumber character varying NOT NULL,
    password character varying NOT NULL,
    created_by character varying,
    created_date timestamp without time zone,
    updated_by character varying,
    updated_date timestamp without time zone
);
 !   DROP TABLE public.tbl_mstr_user;
       public         heap    sadhelx_usr    false            �            1259    16393    tbl_trx_activity    TABLE       CREATE TABLE public.tbl_trx_activity (
    activity_id character varying NOT NULL,
    activity_name character varying NOT NULL,
    activity_session character varying NOT NULL,
    activity_time time without time zone NOT NULL,
    activity_username character varying NOT NULL
);
 $   DROP TABLE public.tbl_trx_activity;
       public         heap    sadhelx_usr    false            �          0    16385    tbl_mstr_user 
   TABLE DATA           �   COPY public.tbl_mstr_user (user_id, username, email, firstname, lastname, phonenumber, password, created_by, created_date, updated_by, updated_date) FROM stdin;
    public          sadhelx_usr    false    200   �       �          0    16393    tbl_trx_activity 
   TABLE DATA           z   COPY public.tbl_trx_activity (activity_id, activity_name, activity_session, activity_time, activity_username) FROM stdin;
    public          sadhelx_usr    false    201   �       0           2606    16392     tbl_mstr_user tbl_mstr_user_pkey 
   CONSTRAINT     c   ALTER TABLE ONLY public.tbl_mstr_user
    ADD CONSTRAINT tbl_mstr_user_pkey PRIMARY KEY (user_id);
 J   ALTER TABLE ONLY public.tbl_mstr_user DROP CONSTRAINT tbl_mstr_user_pkey;
       public            sadhelx_usr    false    200            2           2606    16400 &   tbl_trx_activity tbl_trx_activity_pkey 
   CONSTRAINT     m   ALTER TABLE ONLY public.tbl_trx_activity
    ADD CONSTRAINT tbl_trx_activity_pkey PRIMARY KEY (activity_id);
 P   ALTER TABLE ONLY public.tbl_trx_activity DROP CONSTRAINT tbl_trx_activity_pkey;
       public            sadhelx_usr    false    201            �      x������ � �      �      x������ � �     