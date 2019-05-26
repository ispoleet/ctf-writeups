## Ghost in the Shellcode 2014 - TrustMeMore (RE 150)
##### 17-19/01/2014 (36hr)
___

### Description: 

We let your ex write a service. Running at trustmemore.2014.ghostintheshellcode.com:7457. 

Password: trust is 74u57 -- but l33t doesn't have a u. Note: This challenge is not NAT-friendly.

___
### Solutcion


We connect to `trustmemore.2014.ghostintheshellcode.com:7457` and we send an RSA
private key:

```C
char rsa_key[4096] = {
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIDfQIBAAKBwQDBIv1Y+afRBbU9NeEhxu3tC2pqYBXqJkyxQd4MYbXKu/12X9Ww\n"
    "mu+DiyGZRqWSDqBtwQ2tAzqdHVoBoVdTStbjj+3rs4l1TS5KfBnGeZQGHvZPEQnB\n"
    "uzRMh2SbySEND+eMz2u5NdB/pG4U++Agoc+pmvmEbkT7asKorXyzchl/pINQJ0kh\n"
    "jrSt96L2mozMbG2VfjtosfXH8mwzhhwSLeK8yO7Bh2eh9gCqERe9si15ZATrehMH\n"
    "ByBrbHfls/LNI+0CAwEAAQKBwQC/itf/ufl5D1QjlJ/mQ8gLY1ryjMCvK7S7xztU\n"
    "xELrAW3qTDk9oSsRJpb30Fy8cc0hjGjnwWAMGeP94ekdLgfYQBIRxEj7EMRsEo/t\n"
    "iv4G5AYbfCZVADhp/Y0GA37H2ZBsy13XZc5lf/4Hecor8VMC2Wv8xVaqxvtDEaui\n"
    "S8G03p7cb/tAfJ2UCJQ+GLD/Jr5EIY+RmsiruKIv8c7Lo0p8Iu+VFwSeI4DeHsjf\n"
    "zPi6okyQtJz5eamBzCWw+4z1twECYQDto5vPc2iXcRz/ff0bN6EohsMK9BvqH4YV\n"
    "0Gos2SPeck5eqHcBaVVLvyTQcV7quT9X2D/FzVVvHXaMi+rLsy+ji53CyNPCEAWT\n"
    "alQjUrbZvs/U41oSFxXAlmtgevmSo5ECYQDQDyTOEFaALYFLuHTrb+OW4cU8bAvb\n"
    "kEAcRf0hgFGmrXEpdgflGPMdMLl8pq+HVNHHvXFsLt6tzub3a+Jajve6lDiXPaY1\n"
    "aj8UcnZIsVLEZ7gwH2eXN7benZ3+9ILflJ0CYG5RfYuYr/1d7XBONKnl8VK2/OSg\n"
    "3jSZ3c1Sq3eWdihWODuJSXXGSGqZmaWKe93LkbReF3zkDb0/mEE20xEtZfguYFaE\n"
    "lImKlowQ2G5tf6UmB6V0xeOQA/Eb400uyZ1hgQJhAMf7lmPe/lXr51hx7ygR/w8a\n"
    "6Ws/a1Ja39SNTVazMUhlc9znT4VcqumG2PNAgH0zAQTdSbUzg+RKeGSftQ1YWDNl\n"
    "ntN4dVboTcOIlbsffi+8hiTzOq315ncpxyC1w0nGXQJgayz47tAFwfwX+jjIzYmo\n"
    "hR6W19nX5bzvjLk+M9KmtvBdvSmbfjD4CyWx7bOUL/qCgVB6pSoOfpnXRBdmmJVH\n"
    "1oxIe44QKb98qurd03l/XVti8a617FzjWGKJBCF78Ucu\n"
    "-----END RSA PRIVATE KEY-----\n"
};
```

Then, we listen on port 22 through sshd service (we also enable port forwarding on router
in order to allow remote connections to come in), server connects back to us and leaves
a file with name `gits` in local directory which contains the flag: 
`OnlyDDTEKWouldDoSomethingThisEvil`.


The captured traffic is shown at [re1_traffic_ver2.pcab](re1_traffic_ver2.pcab).

___