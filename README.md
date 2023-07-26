# Store and generate ethereum private key
1. generate and save to android keystem AES key in Android KeyStore
2. generate ethereum key pair by using web3j library
3. Encrypt ethereum private key by using AES key from point 1
4. save encrypted private key to android share preferences

# Get ethereum private key
1. get encrypted private key from shared preferences
2. decrypt it by using AES key
