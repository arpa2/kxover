# KXOVER Configuration

> *Choices to be made, ways to enforce them.*

Syntax of settings follows Erlang expression syntax
and conventions, since we implemented in this language.


## App File

The following settings can be made in the environment of
the `kxover.app` file, found in the `kxover-$VERSION/ebin`
directory produced by the build scripts.  The settings
originate from the source file `process/Makefile.in`,
where they are set in the `PROJECT_ENV` variable.

The value of this variable is a list of tuples, where each
tuple starts with a setting name/identifier followed by
the setting.

As an example, this could be a valid environment:
```
[ { root_certs,<<"/etc/ssl/cert.pem">> } ]
```

This defines a list between `[` and `]` with one tuple between
`{` and `}`.  The name/identifier for the configuration
setting is `root_certs` which is, true to Erlang principles
mentioned without its optional single quotes; in Erlang, an
identifier is part of a system-global enum symbol table.


## Root Certificates / Federated Trust Basis

The configuration variable `root_certs` is optional.
When **absent**, it indicates that any root certificate
is acceptable.  When **present**, it constrains the
trust paths to those that end in one of the certificates
listed.  The latter situation can be used to allow only
trusted certificate authorities (as is commonly done for
web browsers) and/or to allow root signers for a
federation.

The value is either a single file name, or a list between
`[` and `]` of file names.  Each file name is a `binary()`
between `<<"` and `">>` and may be an absolute or relative
path.  Relative paths start from the directory from which
the Erlang program is started (and is not advised except,
perhaps, during testing).

Files may contain any number of certificates in PEM format,
possibly interspersed with textual information such as a
dump of the certificates contained.  The complete set of
`root_certs` consists of all PEM-formatted certificates
in all files configured by this setting.

An **empty** list of root certificates, such as when the
configuration only lists empty files or is an empty list,
implies that no root certificate is acceptable.  It is not
the same as an absent list.

A few alternative configurations serve to demonstrate how this
setting can be used; where the surrounding `[` and `]` of the
environment for all settings are not shown:

 1. `{ root_certs,<<"/etc/ssl/cert.pem">> }`
 2. `{ root_certs,[<<"/etc/ssl/cert.pem">>] }`
 3. `{ root_certs,[<<"selfsig-cert.pem">>,<<"/etc/ssl/cert.pem">>] }`


