
# lab 1 : JWT authentication bypass via unverified signature

> /login using credentials
where you get a jwt token in which we edit the payload from username -> administrator
to get admin priviledge

> /admin
using burp we intercept the /admin and where we modifiy the sub from 
username -> administrator and send the request 

> admin privilege abuse
using the admin privilege we gained we can delete/modifiy users.

# lab 2 : Lab: JWT authentication bypass via flawed signature verification

> all same as the first lab here the difference is alg

in the jwt header the alg is mentioned to be rsa so we need to change that to none 
in order to gain access and authorize into adminstrator.

# lab 3 : JWT authentication bypass via weak signing key

>

# lab 4 :  JWT authentication bypass via jku header injection

# lab 5 : 

# lab 6 : JWT authentication bypass via algorithm confusion 
> public key look-for for rsa
/.well-known/jwks.json
/jwks.json
/auth/jwks
/api/jwks
/keys
/security/jwks
/public-keys


in these list /jwks.json got 200 after the intruder attack use these payloads

jwt_tool <fresh_RS256_token> -X k -pk key.pem -I -pc sub -pv administrator


# lab 7 : JWT authentication bypass via algorithm confusion with no exposed key 

> 
