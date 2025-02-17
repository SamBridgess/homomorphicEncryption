# Implementation guide

## Server side
First of all, you will have to generate Secret and Public
keys for homomorphic encryption. The implementation below
first checks if there is a `keys.json` in a root folder of
the server and if there is, the keys from it. In case if
the specified json was not found, it generates a new one
along with new keys and saves them to the specified json
``` go
homomorphic_encryption_lib.LoadOrGenerateKeys("keys.json")
```

To start the https server, use `StartSecureServer` with port 
passed without `:`
``` go
homomorphic_encryption_lib.StartSecureServer("port")
```

Encryption and decryption of data is done by `EncryptCKKS(data)` 
and `DecryptCKKS(data)`, taking `float64` as an argument. Notice,
that if you store your encrypted data anywhere, the Secret and Public
keys should be the same for encryption and decryption.

## Client side
Before everything, you will have to retrieve CKKS Parameters
from server, which will be required for the future calculations
``` go
ckksParams, err := homomorphic_encryption_lib.GetCKKSParamsFromServer("https://ip_address:port/get_ckks_params")
```

Then client is free to retrieve homomorphicaly encrypted data
any way they can from database. Notice that the `retrievedData` must be stored 
in `[]byte`


To make calculations simply use one of the calculation functions 
from the package, we will use `MultOf2` as an example
``` go
encryptedResult, err := homomorphic_encryption_lib.MultOf2(retrievedData, retrievedData, ckksParams)
```

After you've done all your calculations, you'll need to send the 
result to the server. This result gets decrypted on the server side 
and gets sent back to the client
``` go
result, err := homomorphic_encryption_lib.SendComputationResultToServer("https://ip_address:port/decrypt_computations", encryptedResult)
```

The interaction is complete and now client may use the result
as it pleases
``` go
fmt.Println(result)
```
