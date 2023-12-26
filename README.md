BlowfishJ
=========

Some (very) fast implementation of the 1994
[Blowfish](https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html)
encryption algorithm implementation in Java (17+). ECB, CBC and CFB.

BlowfishJ got introduced in the early days of Java, when the first JIT became
available. It has been updated and maintained ever since.

The CFB mode is compatible with OpenSSL.

It's a Maven project, so just:
```
mvn package
mvn install
```

Copyright 1997-2023 mchahn, Apache 2.0 License.
