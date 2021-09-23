# analytical-env-hive-custom-auth

## DataWorks Analytical Environment custom authentication provider for HiveServer 2

This repo provides a custom authenticator for Hive which requires a valid JWT token for a user to represent the password.
The plugin is done via [Pluggable Authentication](https://docs.cloudera.com/documentation/enterprise/6/6.3/topics/cdh_sg_hiveserver2_security.html#concept_hdt_ngx_nm) which specifies the changes required to the hive site files.

See the [aws-analytical-env](http://github.com/dwp/aws-analytical-env) repository for where it is used.
