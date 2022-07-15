(defproject clj-oauth "1.5.6-SNAPSHOT"
  :url "https://github.com/drone-rites/clj-oauth"
  :license {:name         "Simplified BSD License"
            :url          "https://opensource.org/licenses/BSD-2-Clause"
            :distribution :repo}
  :description "OAuth support for Clojure"
  :dependencies [[org.clojure/clojure "1.10.3"]
                 [commons-codec/commons-codec "1.15"]
                 [org.bouncycastle/bcprov-jdk15on "1.70"]
                 [org.bouncycastle/bcpkix-jdk15on "1.70"]
                 [clj-http "3.12.3"]
                 [com.cemerick/url "0.1.1"]])
