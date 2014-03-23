# OAuth support for Clojure #

`clj-oauth` provides [OAuth](http://oauth.net) Client support for Clojure programs.

# Installing #

Add `[clj-oauth "1.5.0"]` as a Leiningen dependency to get the latest release.

# Building #

`lein jar`

# Running Tests #

Create a file test/oauth/twitter_keys.clj that contains the consumer key and secret.

``` clojure
(def consumer-key "blah")
(def consumer-secret "itsasecret")
```

`lein test`

# Client Example #
``` clojure
    (require ['oauth.client :as 'oauth])
    
    ;; Create a Consumer, in this case one to access Twitter.
    ;; Register an application at Twitter (https://dev.twitter.com/apps/new)
    ;; to obtain a Consumer token and token secret.
    (def consumer (oauth/make-consumer <consumer-token>
                                       <consumer-token-secret>
                                       "https://api.twitter.com/oauth/request_token"
                                       "https://api.twitter.com/oauth/access_token"
                                       "https://api.twitter.com/oauth/authorize"
                                       :hmac-sha1))

    ;; Fetch a request token that a OAuth User may authorize
    ;; 
    ;; If you are using OAuth with a desktop application, a callback URI
    ;; is not required. 
    (def request-token (oauth/request-token consumer <callback-uri>))

    ;; Send the User to this URI for authorization, they will be able 
    ;; to choose the level of access to grant the application and will
    ;; then be redirected to the callback URI provided with the
    ;; request-token.
    (oauth/user-approval-uri consumer 
                             (:oauth_token request-token))

    ;; Assuming the User has approved the request token, trade it for an access token.
    ;; The access token will then be used when accessing protected resources for the User.
    ;;
    ;; If the OAuth Service Provider provides a verifier, it should be included in the
    ;; request for the access token.  See [Section 6.2.3](http://oauth.net/core/1.0a#rfc.section.6.2.3) of the OAuth specification
    ;; for more information.
    (def access-token-response (oauth/access-token consumer 
                                                   request-token
                                                   <verifier>))

    ;; Each request to a protected resource must be signed individually.  The
    ;; credentials are returned as a map of all OAuth parameters that must be
    ;; included with the request as either query parameters or in an
    ;; Authorization HTTP header.
    (def credentials (oauth/credentials consumer
                                        (:oauth_token access-token-response)
                                        (:oauth_token_secret access-token-response)
                                        :POST
                                        "http://api.twitter.com/1.1/statuses/update.json"
                                        {:status "posting from #clojure with #oauth")))

    ;; Post with clj-http...
    (http/post "http://api.twitter.com/1.1/statuses/update.json" 
               :query-params credentials)
                                         
    ;; ...or with clojure-twitter (http://github.com/mattrepl/clojure-twitter)
    (require 'twitter)
    
    (twitter/with-oauth consumer 
                        (:oauth_token access-token-response)            
                        (:oauth_token_secret access-token-response)
                        (twitter/update-status "using clj-oauth with clojure-twitter"))
```

# Authors #

Development funded by LikeStream LLC (Don Jackson and Shirish Andhare), see [http://www.likestream.org/opensource.html](http://www.likestream.org/opensource.html).

Designed and developed by Matt Revelle.

Contributions from Richard Newman.
