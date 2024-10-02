# OpenID Connect 1.0 library for Relying Party

[![Testing](https://github.com/krdlab/haskell-oidc-client/workflows/Testing/badge.svg)](https://github.com/krdlab/haskell-oidc-client/actions?query=workflow%3ATesting)

This package supports implementing of an OpenID Connect 1.0 Relying Party. It's written in Haskell.

This package uses [jose-jwt](http://github.com/tekul/jose-jwt) package for decoding a received tokens.

## Usage

```sh
$ cabal update
$ cabal install oidc-client
```

The documentation is available in [Hackage](https://hackage.haskell.org/package/oidc-client).

## Run example

`examples/scotty` is a runnable code. If you try to run it, execute commands as follows:

```sh
stack build --flag oidc-client:build-examples
```

and then

```sh
stack build --flag oidc-client:build-examples && \
OPENID_CLIENT_BASE_URL="http://localhost:3000" \
OPENID_CLIENT_ID="8e4cf68b-5159-4837-93c3-20714bac76ee" \
OPENID_CLIENT_SECRET="..." \
stack exec scotty-example
```

You can access to <http://localhost:3000/login>.
