(ns datomic.codeq.analyzers.pom
  (:require [datomic.api :as d]
            [datomic.codeq.util :refer [cond-> index->id-fn tempid?]]
            [datomic.codeq.analyzer :as az]
            [clj-xpath.core :as x]
            [clojure.string :as str]
            [clojure.pprint :refer [pprint]])
  (:import  [java.io StringWriter]
            [java.net URI]
            [javax.xml.transform OutputKeys Transformer TransformerException TransformerFactory]
            [javax.xml.transform.dom DOMSource]
            [javax.xml.transform.stream StreamResult]))

;;; Thanks to Jonas Enlund. This is modeled after his Java analyzer.

;;; Parser - convert POM to nested maps

(defn dom [s] (x/xml->doc s))

(defn src [node]
  (az/ws-minify
   (let [n (:node node)
         sw (StringWriter.)
         t  (.. TransformerFactory newInstance newTransformer)]
     (.setOutputProperty t OutputKeys/OMIT_XML_DECLARATION "yes")
     (.transform t (DOMSource. n) (StreamResult. sw))
     (.toString sw))))

(defn project [d] (first (x/$x "/project" d)))

(defmulti parse* :tag)

(defn parse [node]
  (let [s (src node)]
    (merge {:src s
            :loc (x/abs-path node)
            :sha (az/sha s)}
           (parse* node))))

(defn parameter [m node k]
  (if-let [cld (first (x/$x k node))]
    (assoc m (keyword k) (:text cld))
    m))

(defn parameters [m node & ps]
  (reduce #(parameter %1 node %2) m ps))

(defn parse-child [m node k]
  (assoc m (keyword k) (map parse (x/$x (str k "/*") node))))

(defn parse-children [m node & clds]
  (reduce #(parse-child %1 node %2) m clds))

(defmethod parse* :project [node]
  (-> {:node :project}
      (parameters node "groupId" "artifactId" "version" "name" "description")
      (parse-children node "licenses" "dependencies")))

(defmethod parse* :dependency [node]
  (-> {:node :dependency}
      (parameters node "groupId" "artifactId" "version" "scope")))

(defmethod parse* :license [node]
  (-> {:node :license}
      (parameters node "url" "name")))

(defmethod parse* :default [node]
  (println "Warning: default parse handler for"  node)
  (:text node))

(defn parse-tree [s]
  (-> s dom project parse))

(comment
  (parse-tree (slurp "pom.xml"))
  )


;;; Analyzer

(defmulti tx-data (fn [db fid ast ctx] (:node ast)))

(defn find-coords [db group artifact version]
  (ffirst (d/q '[:find ?e :in $ ?g ?a ?v
                 :where [?e :pom/group ?g]
                        [?e :pom/artifact ?a]
                        [?e :pom/version ?v]]
               db group artifact version)))

(defn find-or-new [db f & args]
  (or (apply f db args)
      (d/tempid :db.part/user)))

(defmethod tx-data :project
  [db fid
   {:keys [sha src loc groupId artifactId version name description dependencies licenses] :as ast}
   {:keys [sha->id loc->codeqid] :as ctx}]
  (let [codeid (sha->id sha)
        codetx (if (tempid? codeid)
                 {:db/id codeid
                  :code/sha sha
                  :code/text src})

        codeqid (loc->codeqid src)

        codeqtx (if (tempid? codeqid)
                  {:db/id codeqid
                   :codeq/file fid
                   :codeq/loc loc
                   :codeq/code codeid}
                  {:db/id codeqid})

        coordid (find-or-new db find-coords groupId artifactId version)

        coordtx (if (tempid? coordid)
                  {:db/id coordid
                   :pom/group groupId
                   :pom/artifact artifactId
                   :pom/version version})
        
        codeqtx (assoc codeqtx
                  :pom/name name
                  :pom/description description
                  :pom/coordinates coordid)

        deptx   (mapcat #(tx-data db fid % (assoc ctx :parent codeqid)) dependencies)
        lictx   (mapcat #(tx-data db fid % (assoc ctx :parent codeqid)) licenses)]
    (remove nil? (concat [codetx codeqtx] deptx lictx))))

(defmethod tx-data :dependency
  [db fid
   {:keys [sha src loc groupId artifactId version scope] :as ast}
   {:keys [sha->id loc->codeqid parent] :as ctx}]
  (let [codeid (sha->id sha)
        codetx (if (tempid? codeid)
                 {:db/id codeid
                  :code/sha sha
                  :code/text src})

        codeqid (loc->codeqid src)

        codeqtx (if (tempid? codeqid)
                  {:db/id codeqid
                   :codeq/file fid
                   :codeq/loc src
                   :codeq/code codeid
                   :codeq/parent parent}
                  {:db/id codeqid})

        depid   (find-or-new db find-coords groupId artifactId version)
        deptx   (if (tempid? depid)
                  {:db/id depid
                   :pom/group groupId
                   :pom/artifact artifactId
                   :pom/version version
                   :pom/_dependency parent}
                  {:db/id parent
                   :pom/dependency depid})]
    (remove nil? [codetx codeqtx deptx])))

(defn find-license [db name url]
  (ffirst (d/q '[:find ?e :in $ ?n ?u
                 :where [?dc :pom/license ?e]
                        [?e :license/url ?u]
                        [?e :license/name ?n]]
               db name url)))

(defmethod tx-data :license
  [db fid
   {:keys [sha src loc name url] :as ast}
   {:keys [sha->id loc->codeqid parent pom] :as ctx}]
  (let [codeid (sha->id sha)
        codetx (if (tempid? codeid)
                 {:db/id codeid
                  :code/sha sha
                  :code/text src})

        codeqid (loc->codeqid src)

        codeqtx (if (tempid? codeqid)
                  {:db/id codeqid
                   :codeq/file fid
                   :codeq/loc src
                   :codeq/code codeid
                   :codeq/parent parent}
                  {:db/id codeqid})
        
        licid   (find-or-new db find-license name url)
        lictx   (if (tempid? licid)
                  {:db/id licid
                   :license/url (URI. url)
                   :license/name name
                   :pom/_license parent}
                  {:db/id parent
                   :pom/license licid})]
    (remove nil? [codetx codeqtx lictx])))

(defn analyze [db fid src]
  (let [ast (parse-tree src)]
    (tx-data db fid ast {:sha->id (index->id-fn db :code/sha)
                                 :codename->id (index->id-fn db :code/name)
                                 :loc->codeqid #(or (ffirst (d/q '[:find ?e :in $ ?f ?src
                                                                   :where [?e :codeq/file ?f]
                                                                          [?e :codeq/loc ?src]]
                                                                 db fid %))
                                                    (d/tempid :db.part/user))})))

(defn schemas []
  {1 [{:db/id #db/id[:db.part/db]
       :db/ident :pom/name
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "project name from maven coordinates"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/url
       :db/valueType :db.type/uri
       :db/cardinality :db.cardinality/one
       :db/doc "version number from maven coordinates"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/description
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "project description string"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/coordinates
       :db/valueType :db.type/ref
       :db/cardinality :db.cardinality/one
       :db/doc "coordinates from the pom"
       :db.install/_attribute :db.part/db}
      
      {:db/id #db/id[:db.part/db]
       :db/ident :pom/group
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "groupId from maven coordinates"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/artifact
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "artifactId from maven coordinates"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/version
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "version number from maven coordinates"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/dependency
       :db/valueType :db.type/ref
       :db/cardinality :db.cardinality/many
       :db/doc "dependencies required by a project"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :pom/license
       :db/valueType :db.type/ref
       :db/cardinality :db.cardinality/many
       :db/doc "license(s) used in a project"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :license/name
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "name of the license"
       :db.install/_attribute :db.part/db}

      {:db/id #db/id[:db.part/db]
       :db/ident :license/url
       :db/valueType :db.type/uri
       :db/cardinality :db.cardinality/one
       :db/doc "url of the license"
       :db.install/_attribute :db.part/db}]})

(deftype PomAnalyzer []
  az/Analyzer
  (keyname [a] :pom)
  (revision [a] 1)
  (extensions [a] ["pom.xml"])
  (schemas [a] (schemas))
  (analyze [a db f src] (analyze db f src)))

(defn impl [] (PomAnalyzer.))

(comment
;;(def uri "datomic:mem://git")
(def uri "datomic:free://localhost:4334/git")
(def conn (d/connect uri))
(def db (d/db conn))

;; clear analysis for re-run
(let [db (d/db conn)]
  (let [eavts (d/q '[:find ?tx :where [?tx :tx/analyzer :pom]] db)]
    (d/transact conn (map #(vector ':db/retract (first %) ':tx/analyzer ':pom) eavts))
    (d/transact conn (map #(vector ':db/retract (first %) ':tx/analyzerRev 1) eavts)))
  (doseq [[dp] (d/q '[:find ?d :where [?d :pom/group]] db)]
    (d/transact conn [[:db.fn/retractEntity dp]])))

(d/q '[:find ?e :where [?f :file/name "pom.xml"] [?n :node/filename ?f] [?n :node/object ?e]] db)
(d/q '[:find ?e :where [?e :pom/dependency]] db)

(d/q '[:find ?d :in $ ?g ?a ?v :where [?d :pom/group ?g] [?d :pom/artifact ?a] [?d :pom/version ?v]] db "org.codehaus.jsr166-mirror" "jsr166y" "1.7.0")

(find-depid db "org.codehaus.jsr166-mirror" "jsr166y" "1.7.0")

(sort (d/q '[:find ?name ?dep :where [?e :pom/name ?name] [?e :pom/dependency ?dep]] db))

(sort (d/q '[:find ?name ?g ?a ?v :where [?e :pom/name ?name] [?e :pom/dependency ?dep] [?dep :pom/group ?g] [?dep :pom/artifact ?a] [?dep :pom/version ?v]] db))

)
