-- This the initiator file for database in postgre for the server initialisation --
create database x3dh;

-- Table to store Each resgitered user's username and password(hash) --
create table User_Info(user_id varchar(100) Primary key, password varchar(100));

-- Table to store identity keys of each registered user --
create table identity_key(user_id varchar(100),
                          identity_key bytea(200),
                          time_stamp_creation varchar(60),
                          time_stamp_last_usage varchar(60),
                          constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store signed keys of each registered user ---
create table signed_key(user_id varchar(100),
                        signed_pre_key bytea(100),
                        signature bytea(100),
                        time_stamp_creation varchar(60),
                        time_stamp_last_usage varchar(60),
                        Constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store onetime_pre_key of each registered user --
create table onetime_pre_key(user_id varchar(100),
                             key_id uuid unique default gen_random_uuid(),
                             one_time_key bytea(100),
                             time_stamp_creation varchar(60),
                             time_stamp_last_usage varchar(60),
                             is_used boolean default false,
                             Constraint fk_user foreign key(user_id) references User_Info(user_id));

