# kdk-ath-infr-test

```bash
export OATHKEEPER_PATH=/path/to/oathkeeper
go run .
```

- **wallet-rule**: `/wallet/*` - Accepts machine tokens, session cookies, or bearer tokens
- **switch-rule**: `/switch/*` - Accepts tokens with either machine or PSP audience
- **shared-rule**: `/shared/*` - Accepts only machine tokens

### Header Mutation

All successful requests will have two headers added:

- **X-Auth-Details**: Base64-encoded JSON of the authentication session
- **X-Auth-Source**: Set based on authentication method:
  - `user` - For cookie or bearer token authentication
  - `machine` - For OAuth2 tokens with machine audience
  - `psp` - For OAuth2 tokens with PSP audience (takes precedence)

To add more test scenarios:

1. Add new tokens to the mock server's introspection handler in `mocks/main.go`
2. Add new test cases to the `testCases` array in `main.go`
3. Update `rules.json` if new access patterns are needed
