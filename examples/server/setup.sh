#!/bin/bash

wget https://dl.google.com/go/go1.23.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz
rm go1.23.5.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile

sudo bash -c 'echo "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin\"" >> /etc/sudoers.d/99-go-path'

/usr/local/go/bin/go version
source ~/.profile

sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib

sudo systemctl start postgresql
sudo systemctl enable postgresql

sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '123456';"

sudo sed -i 's/local   all             postgres                                peer/local   all             postgres                                md5/' /etc/postgresql/*/main/pg_hba.conf

sudo systemctl restart postgresql

sudo -u postgres psql <<EOF
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
EOF

sudo apt-get autoremove -y
sudo apt-get clean

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -config openssl.cnf
sudo cp cert.pem /usr/local/share/ca-certificates/my_cert.crt
sudo update-ca-certificates

go mod tidy

echo "Setup complete. Go 1.23.5 and PostgreSQL installed and configured."