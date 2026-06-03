curl -i -X POST http://127.0.0.1:3000/api/auth/register \
-H "Content-Type: application/json" \
-d '{
  "username": "test_user_1",
  "password": "super_secure_password",
  "key_bundle": {
    "identity_key": "base64_encoded_identity_key_string",
    "identity_key_dh": "base64_encoded_dh_key_string",
    "signed_pre_key": "base64_encoded_signed_pre_key",
    "signature": "base64_encoded_signature",
    "one_time_pre_keys": {
      "1": "base64_otpk_value_1",
      "2": "base64_otpk_value_2"
    }
  }
}'

access_key=$(curl -s -X POST http://127.0.0.1:3000/api/auth/login \
-H "Content-Type: application/json" \
-d '{
  "username": "test_user_1",
  "password": "super_secure_password"
}' | jq -r '.access_token')

echo "Access Key: $access_key"

curl -i -X POST http://127.0.0.1:3000/api/auth/ws_ticket \
-H "Authorization: Bearer $access_key"
