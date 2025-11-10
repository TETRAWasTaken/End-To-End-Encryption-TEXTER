-- This the initiator file for a database in postgre for the server initialization --
create database x3dh;

-- Table to store Each registered user's username and password(hash) --
create table User_Info(user_id varchar(100) Primary key, password varchar(100));

-- Table to store identity keys of each registered user --
create table identity_key(user_id varchar(100),
                          identity_key bytea,
                          time_stamp_creation varchar(60),
                          time_stamp_last_usage varchar(60),
                          constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store signed keys of each registered user ---
create table signed_key(user_id varchar(100),
                        signed_pre_key bytea,
                        signature bytea,
                        time_stamp_creation varchar(60),
                        time_stamp_last_usage varchar(60),
                        Constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store onetime_pre_key of each registered user --
create table onetime_pre_key(user_id varchar(100),
                             key_id int unique,
                             one_time_key bytea,
                             time_stamp_creation varchar(60),
                             time_stamp_last_usage varchar(60),
                             is_used boolean default false,
                             Constraint fk_user foreign key(user_id) references User_Info(user_id));

-- Table to store live sessions of each registered user --
create table sessions(user_one varchar(100),
                      user_two varchar(100),
                      session_id uuid default gen_random_uuid(),
                      constraint fk_userone foreign key(user_one) references user_info(user_id),
                      constraint fk_usertwo foreign key(user_two) references user_info(user_id));

-- Table to store encrypted text_cache of each registered user --
create table text_cache(sender_id varchar(100),
                        receiver_id varchar(100),
                        text_cache text,
                        flag boolean default false, -- flag to indicate if a text was sent or not, true for sent, false for not sent
                        time_stamp_creation varchar(60),
                        time_stamp_last_usage varchar(60) default Null,
                        Constraint fk_user foreign key(sender_id) references User_Info(user_id));