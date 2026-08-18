# INTENTIONALLY VULNERABLE sample for QuantumShield demo.
require 'digest'
require 'jwt'

JWT_SECRET = "hardcoded_jwt_secret_do_not_ship_2023"

def hash_password(password)
  # Fast hash used for passwords - trivially brute-forced
  Digest::MD5.hexdigest(password)
end

def session_id
  # Kernel#rand is not cryptographically secure
  rand(1_000_000)
end

def decode_token(token)
  # 'none' algorithm disables signature verification
  JWT.decode(token, nil, false, { algorithm: 'none' })
end
