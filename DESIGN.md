# High-Level Design

## User Flow

1. User loads Foundry docs for a private dataset on $domain
2. Foundry detects the 403, redirects them to https://proxy.dev.socrata.com/auth/socrata?domain=$domain
3. Proxy authenticates them via $proxy, sets a session cookie with their auth token on proxy.dev.socrata.com, and one with their login details on dev.socrata.com (Can I do that?)
4. Proxy redirects user back to /foundry/#/$domain/$uid/private
5. Foundry requests hit the proxy.dev.socrata.com/resource/$uid endpoints instead of the API directly
