-- This the initiator file for database in postgre for the server initialisation --
create database x3dh;

-- Table to store Each resgitered user's username and password(hash) --
create table User_Info(user_id varchar(100) Primary key, password varchar(100));

-- Table to store identity keys of each registered user --
create table identity_key(user_id varchar(100),
                          key_id int unique,
                          identity_key varchar(200),
                          time_stamp_creation varchar(60),
                          time_stamp_last_usage varchar(60),
                          constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store signed keys of each registered user ---
create table signed_key(user_id varchar(100),
                        key_id int unique,
                        signed_pre_key varchar(100),
                        signature varchar(100),
                        time_stamp_creation varchar(60),
                        time_stamp_last_usage varchar(60),
                        Constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store onetime_pre_key of each registered user --
create table onetime_pre_key(user_id varchar(100),
                             key_id int unique,
                             one_time_key varchar(100),
                             time_stamp_creation varchar(60),
                             time_stamp_last_usage varchar(60),
                             Constraint fk_user foreign key(user_id) references User_Info(user_id));

