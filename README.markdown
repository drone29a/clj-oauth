# OAuth Consumer support for Clojure #

This is a pre-release, use at your own risk!

`clj-oauth` provides [OAuth](http://oauth.net) consumer support for Clojure programs.


# Example #

    (require ['oauth.client :as 'oc])
    
    (def consumer (oc/make-consumer <consumer-token>
                                    <consumer-token-secret>
                                    "http://twitter.com/oauth/request_token"
                                    "http://twitter.com/oauth/access_token"
                                    "http://twitter.com/oauth/authorize"
                                    :hmac-sha1))

    ;; Fetch request token
    (def request-token (:oauth_token (oc/request-token consumer)))

    ;; Redirect the OAuth User to this URI for authorization
    (def approval-uri (oc/user-approval-uri consumer 
                                            request-token)

    ;; Assuming the User has approved the request token, trade it for an access token
    (def access-token (:oauth_token (oc/access-token consumer
                                                     request-token)))

    ;; The access token may be used with our other Consumer credentials to authorize requests
    (def credentials (oc/sign-request consumer
                                      access-token
                                      :POST
                                      "http://twitter.com/statuses/update.json"
                                      <update-params>))

    (http/post "http://twitter.com/statuses/update.json" 
               :query (merge credentials <update-params>)))
                                         
