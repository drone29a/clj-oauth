(defproject clj-oauth "1.3.0-SNAPSHOT"
  :description "OAuth support for Clojure"
  :repositories {"snapshots" {:url "s3p://lein-snapshots/snapshots"}}
  :dependencies [[org.clojure/clojure "1.3.0"]
                 [com.twinql.clojure/clj-apache-http "2.3.2-SNAPSHOT"]
                 [org.apache.httpcomponents/httpclient "4.1"]
                 [org.apache.httpcomponents/httpcore "4.1"]
                 [org.apache.httpcomponents/httpmime "4.1"]])
