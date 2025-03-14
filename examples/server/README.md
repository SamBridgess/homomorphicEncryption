# Server guide

For quick installation on a clean system you can use `setup.sh` scrypt, located in this directory.
Run

```commandline
./setup.sh
```
from this directory. In case you are at any point asked for `postgres` password, use `123456.

After running the crypt, use 
```commandline
source ~/.profile
```
in the working terminal, so that current terminal updates to the changes made in the script
unfortunately, this command can not be included into script in order for in to work properly.

## Running Server
To quickly test-run the server app, type
``` commandline
sudo go run server.go
```
in the command line in the root folder of the server. Notice,
that executing from the root folder is yet mandatory. Also notice, that unlike
`client.go`, `server.go` must be run with `sudo`

## Certificates
HTTPS requires secured connection. If your goal is simply
trying examples out on your local machine, you can generate
it yourself. First, create `openssl.cnf` file in the root
folder of the server with the following content(it's already present in
this repo, but look through its content anyway:
``` 
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = 127.0.0.1

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
```

Generate `cert.pem` and `key.pem`
``` commandline
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -config openssl.cnf
sudo cp cert.pem /usr/local/share/ca-certificates/my_cert.crt
sudo update-ca-certificates
```
If you want to make a real certificate, change the `.cnf` file for
your own purposes

## Keys
Upon starting, `server.go` automatically loads `bfvKeys.json` and `ckksKeys.json`
files if they are present in a root folder. In case they are not present, application
will generate new key files. Notice, that if you remove key files, all data encrypted
using them will not be available for decryption, because newly generated keys will not
fit for decryption of files encrypted with different keys. `bfvKeys.json` and `ckksKeys.json`
are left in this folder just for an example, but are still valid and can be used for
decryption and encryption as is

## Database
One last step before running the application is configuring a database. In this case,
we would need two users, admin(for server) and client. Now, lets assume that there is
already configured postgres running on your PC, and you have the following credentials 
for admin server user:
```golang
// This code was taken from server.go
const (
	host           = "localhost"
	port           = 5432
	userServer     = "postgres"
	passwordServer = "123456"
	dbname         = "encrypted_db"
)
```

In order to create out working table, you will have to execute the following script.
it also creates a `client` user who only have read permissions for our example
`encrypted_data_ckks_bfv` table:
```sql
CREATE DATABASE encrypted_db;

\c encrypted_db;

CREATE TABLE encrypted_data_ckks_bfv (
    id SERIAL PRIMARY KEY,
    encryptedDataCkks1 BYTEA,
    encryptedDataCkks2 BYTEA,
    encryptedDataCkks3 BYTEA,
    encryptedDataCkks4 BYTEA,
    encryptedDataCkks5 BYTEA,

    encryptedDataBfv1 BYTEA,
    encryptedDataBfv2 BYTEA,
    encryptedDataBfv3 BYTEA,
    encryptedDataBfv4 BYTEA,
    encryptedDataBfv5 BYTEA
);

CREATE USER client WITH PASSWORD '123456';
GRANT SELECT ON encrypted_data_ckks_bfv TO client;
```

