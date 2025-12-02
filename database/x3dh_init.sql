-- Drop existing tables in reverse order of creation to handle dependencies.
DROP TABLE IF EXISTS text_cache;
DROP TABLE IF EXISTS onetime_pre_key;
DROP TABLE IF EXISTS signed_key;
DROP TABLE IF EXISTS identity_key;
DROP TABLE IF EXISTS User_Info;
DROP TABLE IF  EXISTS friend_requests;

-- Table to store each registered user's username and a secure password hash.
CREATE TABLE User_Info (
    user_id VARCHAR(100) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    time_stamp_creation TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table to store the long-term identity key of each registered user.
-- Storing as TEXT (Base64 encoded string).
CREATE TABLE identity_key (
    user_id VARCHAR(100) PRIMARY KEY,
    identity_key TEXT NOT NULL,       -- The Ed25519 Key (Signing)
    identity_key_dh TEXT NOT NULL,    -- The X25519 Key (Diffie-Hellman) -- NEW COLUMN
    time_stamp_creation TIMESTAMPTZ NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES User_Info(user_id) ON DELETE CASCADE
);

-- Table to store signed pre-keys of each registered user.
-- Storing as TEXT (Base64 encoded string).
CREATE TABLE signed_key (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    signed_pre_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    time_stamp_creation TIMESTAMPTZ NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES User_Info(user_id) ON DELETE CASCADE
);

-- Index to quickly find the latest signed_key for a user.
CREATE INDEX idx_signed_key_user_time ON signed_key (user_id, time_stamp_creation DESC);

-- Table to store one-time pre-keys for each registered user.
-- Storing as TEXT (Base64 encoded string).
CREATE TABLE onetime_pre_key (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    key_id BIGINT NOT NULL,
    one_time_key TEXT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    time_stamp_creation TIMESTAMPTZ NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES User_Info(user_id) ON DELETE CASCADE,
    UNIQUE (user_id, key_id)
);

-- Index to efficiently find an available one-time key for a user.
CREATE INDEX idx_onetime_key_user_is_used ON onetime_pre_key (user_id, is_used);

-- Table to store encrypted text_cache for offline messaging.
CREATE TABLE text_cache (
    id SERIAL PRIMARY KEY,
    sender_id VARCHAR(100) NOT NULL,
    receiver_id VARCHAR(100) NOT NULL,
    text_cache TEXT NOT NULL,
    flag BOOLEAN NOT NULL DEFAULT FALSE,
    time_stamp_creation TIMESTAMPTZ NOT NULL,
    time_stamp_last_usage TIMESTAMPTZ, -- Added this column
    CONSTRAINT fk_sender FOREIGN KEY(sender_id) REFERENCES User_Info(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_receiver FOREIGN KEY(receiver_id) REFERENCES User_Info(user_id) ON DELETE CASCADE
);

-- Index to quickly retrieve cached messages for a receiver.
CREATE INDEX idx_text_cache_receiver ON text_cache (receiver_id);

-- A ENUM type to represent the status of a friend request.
CREATE TYPE status_type AS ENUM ('pending', 'accepted', 'rejected', 'blocked');

-- Table to keep track of friends and their statuses.
CREATE TABLE friends (
    friend_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_one_id VARCHAR(100) NOT NULL,
    user_two_id VARCHAR(100) NOT NULL,
    status status_type NOT NULL,

    CONSTRAINT fk_user_one FOREIGN KEY(user_one_id) REFERENCES User_Info(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_two FOREIGN KEY(user_two_id) REFERENCES User_Info(user_id) ON DELETE CASCADE
);