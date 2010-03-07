(ns 
    #^{:author "Pelle Braendgaard"
       :doc "OAuth Token store"} 
  oauth.token-store
)

;; Return a Consumer record based on consumer key.
;; If a consumer is returned then it is assumed to be valid
(defmulti consumer-get 
  "Get consumer from store"
  (fn [c _] c))

;; Stores a consumer. The 2 required fields in the map are :key and :secret
(defmulti consumer-put 
  "Stores consumer"
  (fn [c _] c))

;; Return a Request Token record based on a token
;; If a token is returned then it is assumed to be valid. Thus expiry etc should be handled in the store.
(defmulti request-token-get 
  "Get valid request-token from store"
  (fn [c _] c))

;; Stores a Request Token. The 3 required fields in the map are :token, :secret and :callback_url
(defmulti request-token-put 
  "Stores request-token"
  (fn [c _] c))

;; Revokes a request token. Implementations can chose to simply delete record. 
;; However once this is called it should no longer be returned by request-token-get
(defmulti request-token-revoke 
  "Revokes a request-token"
  (fn [c _] c))

;; Return a Request Token record based on a token
;; If a token is returned then it is assumed to be valid. Thus expiry etc should be handled in the store.
(defmulti access-token-get 
  "Get valid access-token from store"
  (fn [c _] c))

;; Stores an Access Token. The 2 required fields in the map are :token and :secret
(defmulti access-token-put 
  "Stores access-token"
  (fn [c _] c))

;; Revokes an access token. Implementations can chose to simply delete record. 
;; However once this is called it should no longer be returned by access-token-get
(defmulti access-token-revoke 
  "Revokes a access-token"
  (fn [c _] c))


(def memory-consumers (atom {}))

(defmethod consumer-get :memory
  [_ key]
    (@memory-consumers key)
  )

(defmethod consumer-put :memory
  [_ consumer]
    ((swap! memory-consumers assoc (consumer :key) consumer) (consumer :key))
  )


(def memory-request-tokens (atom {}))

(defmethod request-token-get :memory
  [_ token]
    (@memory-request-tokens token)
  )

(defmethod request-token-put :memory
  [_ token]
    ((swap! memory-request-tokens assoc (token :token) token) (token :token))
  )

(defmethod request-token-revoke :memory
  [_ token]
    (swap! memory-request-tokens dissoc token )
  )

(def memory-access-tokens (atom {}))

(defmethod access-token-get :memory
  [_ token]
    (@memory-access-tokens token)
  )

(defmethod access-token-put :memory
  [_ token]
    ((swap! memory-access-tokens assoc (token :token) token) (token :token))
  )

(defmethod access-token-revoke :memory
  [_ token]
    (swap! memory-access-tokens dissoc token )
  )
