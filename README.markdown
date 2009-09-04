# OAuth Consumer support for Clojure #

`clj-oauth` provides [OAuth](http://oauth.net) Consumer support for Clojure programs.

The library depends on Richard Newman's [clj-apache-http](http://github.com/rnewman/clj-apache-http) which includes Apache's
HTTP components.  The Apache Commons Codec library is also required.  All dependencies
are included in `lib` directory of the repository.

# Building #

`ant -Dclojure.jar="..." -Dclojure.contrib.jar="..."`

# Example #

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
    (def request-token (:oauth_token (oauth/request-token consumer)))

    ;; Send the User to this URI for authorization, they will be able 
    ;; to choose the level of access to grant the application and will
    ;; then be redirected to the callback URI provided.
    (oauth/user-approval-uri consumer 
                             request-token
                             <callback-uri>)

    ;; Assuming the User has approved the request token, trade it for an access token.
    ;; The access token will then be used when accessing protected resources for the User.
    (def access-token-response (:oauth_token (oauth/access-token consumer
                                                                 request-token)))

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

# Authors #

Development funded by LikeStream LLC (Don Jackson and Shirish Andhare), see [http://www.likestream.org/opensource](http://www.likestream.org/opensource).

Designed and developed by Matt Revelle of [Lightpost Software](http://lightpostsoftware.com).

Contributions from Richard Newman.