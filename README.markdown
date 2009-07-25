# OAuth Consumer support for Clojure #

This is a pre-release, use at your own risk!

`clj-oauth` provides [OAuth](http://oauth.net) consumer support for Clojure programs.


# Example #

    (require ['oauth.client :as 'oauth])
    
    (def consumer (oauth/make-consumer <consumer-token>
                                       <consumer-token-secret>
                                       "http://twitter.com/oauth/request_token"
                                       "http://twitter.com/oauth/access_token"
                                       "http://twitter.com/oauth/authorize"
                                       :hmac-sha1))

    ;; Fetch request token
    (def request-token (:oauth_token (oauth/request-token consumer)))

    ;; Redirect the OAuth User to this URI for authorization
    (def approval-uri (oauth/user-approval-uri consumer 
                                               request-token
                                               <callback-uri>))

    ;; Assuming the User has approved the request token, trade it for an access token
    (def access-token (:oauth_token (oauth/access-token consumer
                                                        request-token)))

    ;; The access token may be used with our other Consumer credentials to authorize requests
    (def credentials (oauth/credentials consumer
                                        access-token
                                        :POST
                                        "http://twitter.com/statuses/update.json"
                                        {:status "posting from #clojure with #oauth")))

    ;; Post with clj-apache-http, or...
    (http/post "http://twitter.com/statuses/update.json" 
               :query (merge credentials 
                             {:status "posting from #clojure with #oauth"})
               :parameters (http/map->params {:use-expect-continue false})))
                                         
    ;; ...with clojure-twitter (http://github.com/mattrepl/clojure-twitter)
    (require 'twitter)
    
    (with-oauth consumer access-token
        (twitter/update-status "using clj-oauth with clojure-twitter"))