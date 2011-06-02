# OAuth support for Clojure #

`clj-oauth` provides [OAuth](http://oauth.net) Client and Server support for Clojure programs.

The client part of the library depends on Richard Newman's [clj-apache-http](http://github.com/rnewman/clj-apache-http) which includes Apache's
HTTP components.

The server support makes it simple to add OAuth support to any [Ring](http://github.com/mmcgrana/ring) based web applications such as Compojure.

# Building #

`lein jar`

# Client Example #

    (require ['oauth.client :as 'oauth])
    
    ;; Create a Consumer, in this case one to access Twitter.
    ;; Register an application at Twitter (http://twitter.com/oauth_clients/new)
    ;; to obtain a Consumer token and token secret.
    (def consumer (oauth/make-consumer <consumer-token>
                                       <consumer-token-secret>
                                       "http://twitter.com/oauth/request_token"
                                       "http://twitter.com/oauth/access_token"
                                       "http://twitter.com/oauth/authorize"
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
                                        "http://twitter.com/statuses/update.json"
                                        {:status "posting from #clojure with #oauth")))

    ;; Post with clj-apache-http...
    (http/post "http://twitter.com/statuses/update.json" 
               :query (merge credentials 
                             {:status "posting from #clojure with #oauth"})
               :parameters (http/map->params {:use-expect-continue false})))
                                         
    ;; ...or with clojure-twitter (http://github.com/mattrepl/clojure-twitter)
    (require 'twitter)
    
    (twitter/with-oauth consumer 
                        (:oauth_token access-token-response)            
                        (:oauth_token_secret access-token-response)
                        (twitter/update-status "using clj-oauth with clojure-twitter"))

# Server Support #

The server support is implemented as Ring middleware. It depends on params middleware already having been run upstream.  The server implementation is incomplete but available in the `server` branch.

# Authors #

Development funded by LikeStream LLC (Don Jackson and Shirish Andhare), see [http://www.likestream.org/opensource.html](http://www.likestream.org/opensource.html).

Designed and developed by Matt Revelle.

Contributions from Richard Newman.

Server implementation by Pelle Braendgaard of [Stake Ventures](http://stakeventures.com)
