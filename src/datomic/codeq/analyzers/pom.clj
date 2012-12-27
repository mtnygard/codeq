(ns datomic.codeq.analyzers.pom
  (:require [datomic.api :as d]
            [datomic.codeq.util :refer [cond-> index->id-fn tempid?]]
            [datomic.codeq.analyzer :as az]
            [clj-xpath.core :as x]
            [clojure.string :as str]
            [clojure.pprint :refer [pprint]])
  (:import  [java.io StringWriter]
            [javax.xml.transform OutputKeys Transformer TransformerException TransformerFactory]
            [javax.xml.transform.dom DOMSource]
            [javax.xml.transform.stream StreamResult]))

;;; Parser - convert POM to nested maps

(defn dom [s] (x/xml->doc s))

(defn src [node]
  (let [n (:node node)
        sw (StringWriter.)
        t  (.. TransformerFactory newInstance newTransformer)]
    (.setOutputProperty t OutputKeys/OMIT_XML_DECLARATION "yes")
    (.transform t (DOMSource. n) (StreamResult. sw))
    (.toString sw)))

(defn loc [node]
  (az/ws-minify (src node)))

(defn parameter [m node k]
  (if-let [cld (first (x/$x k node))]
    (assoc m (keyword k) (:text cld))
    m))

(defn parameters [m node & ps]
  (reduce #(parameter %1 node %2) m ps))

(defn child [m node k]
  (assoc m (keyword k) (map parse (x/$x (str k "/*") node))))

(defn children [m node & clds]
  (reduce #(child %1 node %2) m clds))

(defn project [d] (first (x/$x "/project" d)))

(defmulti parse* :tag)

(defn parse [node]
  (let [l (loc node)]
    (merge {:loc l
            :sha (az/sha l)}
           (parse* node))))

(defmethod parse* :project [node]
  (-> {:node :project}
      (parameters node "groupId" "groupId" "artifactId" "version" "name" "description")
      (children node "licenses" "dependencies")))

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







(defn dom-node->string
  [n]
  (let [node (:node n)
        sw (StringWriter.)
        t  (.. TransformerFactory newInstance newTransformer)]
    (.setOutputProperty t OutputKeys/OMIT_XML_DECLARATION "yes")
    (.transform t (DOMSource. node) (StreamResult. sw))
    (.toString sw)))

(defn sha->id
  [db sha]
  ((index->id-fn db :code/sha) sha))

(defn sha
  [content]
  (-> content
      az/ws-minify
      az/sha))

(defn maybe-new-codeq
  [{:keys [db f ret added] :as state} loc contents]
  (let [sha       (sha contents)
        codeid    (sha->id db sha)
        newcodeid (and (tempid? codeid) (not (added codeid)))
        ret       (cond-> ret
                          newcodeid
                          (conj {:db/id codeid
                                 :code/sha sha
                                 :code/text contents}))
        added     (cond-> added
                          newcodeid
                          (conj codeid))

        codeqid   (or (ffirst (d/q '[:find ?e :in $ ?f ?loc
                                     :where [?e :codeq/file ?f]
                                            [?e :codeq/loc ?loc]]
                                   db f loc))
                      (d/tempid :db.part/user))

        ret       (cond-> ret
                          (tempid? codeqid)
                          (conj {:db/id codeqid
                                 :codeq/file f
                                 :codeq/loc loc
                                 :codeq/code codeid}))]
    [codeqid (assoc state :ret ret :added added)]))

(defn xpath->attribute
  [{:keys [db f dom ret added] :as state} path attribute]
  (if-let [node (first (x/$x path dom))]
    (let [contents            (dom-node->string node)
          [codeqid state]     (maybe-new-codeq state path contents)]
      (update-in state [:ret] conj [:db/add f attribute contents]))
    state))

(defn find-depid
  [db group artifact version]
  (ffirst (d/q '[:find ?d
                 :in $ ?g ?a ?v
                 :where [?d :pom/group ?g]
                        [?d :pom/artifact ?a]
                        [?d :pom/version ?v]]
               db group artifact version)))

(defn maybe-new-dependency
  [{:keys [db added ret] :as state} {:keys [groupId artifactId version]}]
  (let [depid  (or (find-depid db groupId artifactId version)
                   (d/tempid :db.part/user))
        added  (cond-> added
                       (tempid? depid)
                       (conj depid))

        ret    (cond-> ret
                       (tempid? depid)
                       (conj {:db/id depid
                              :pom/group groupId
                              :pom/artifact artifactId
                              :pom/version version}))]
    [depid (assoc state :added added :ret ret)]))

(defn find-licid
  [db name url]
  (ffirst (d/q '[:find ?l
                 :in $ ?n ?u
                 :where [?l :license/name ?n]
                 [?l :license/url ?u]]
               db name url)))

(defn maybe-new-license
  [{:keys [db added ret] :as state} {:keys [name url]}]
  (let [licid  (or (find-licid db name url)
                   (d/tempid :db.part/user))
        added  (cond-> added
                       (tempid? licid)
                       (conj licid))
        ret    (cond-> ret
                       (tempid? licid)
                       (conj {:db/id licid
                              :license/name name
                              :license/url url}))]
    [licid (assoc state :added added :ret ret)]))

(defn child-with-tag
  [n t]
  (first (filter #(= t (:tag %)) @(:children n))))

(defn tag-contents-as-key
  [m node k]
  (cond-> m
          (child-with-tag node k)
          (assoc k (:text (child-with-tag node k)))))

(defn dom->dep
  [node]
  (-> {}
      (assoc :content (dom-node->string node))
      (assoc :path    (str "/project/dependencies[artifactId=\""
                           (:text (child-with-tag node :artifactId))
                           "\"]"))
      (tag-contents-as-key node :groupId)
      (tag-contents-as-key node :artifactId)
      (tag-contents-as-key node :version)))

(defn dependency-1
  [{:keys [f] :as state} {:keys [path content] :as d}]
  (let [[codeqid state]     (maybe-new-codeq state path content)
        [depid   state]     (maybe-new-dependency state d)
        ret                 (cond-> (:ret state)
                                    (or (tempid? depid) ((:added state) depid))
                                    (conj [:db/add f :pom/dependency depid]))]
    (assoc state :ret ret)))

(defn dom->license
  [node]
  (-> {}
      (assoc :content (dom-node->string node))
      (assoc :path    (str "/project/licenses[name=\""
                           (:text (child-with-tag node :name))
                           "\"]"))
      (tag-contents-as-key node :name)
      (tag-contents-as-key node :url)))

(defn license-1
  [{:keys [f] :as state} {:keys [path content name url] :as l}]
  (let [[codeqid state]     (maybe-new-codeq state path content)
        [licid   state]     (maybe-new-license state l)
        ret                 (cond-> (:ret state)
                                    (or (tempid? licid) ((:added state) licid))
                                    (conj [:db/add f :pom/license licid]))]
    (assoc state :ret ret)))

(defn multivalue-nodes
  [{:keys [dom] :as state} parent-xpath node-extractor-fn datomic-upsert-fn]
  (let [nodes (x/$x parent-xpath dom)]
    (cond-> state
            nodes
            ((fn [st] (reduce datomic-upsert-fn st (map node-extractor-fn nodes)))))))

(defn dependencies
  [state]
  (multivalue-nodes state "/project/dependencies/*" dom->dep dependency-1))

(defn licenses
  [state]
  (multivalue-nodes state "/project/licenses/*" dom->license license-1))

(defn analyze
  [db f src]
  (-> {:db       db
       :f        f
       :dom      (x/xml->doc src)
       :added    #{}
       :ret      []}
      (xpath->attribute "/project/artifactId"  :pom/artifact)
      (xpath->attribute "/project/groupId"     :pom/group)
      (xpath->attribute "/project/name"        :pom/name)
      (xpath->attribute "/project/version"     :pom/version)
      (xpath->attribute "/project/description" :pom/description)
      (dependencies)
      (licenses)
      :ret))

(defn schemas []
  {1 [{:db/id #db/id[:db.part/db]
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
       :db/ident :pom/name
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "project name from maven coordinates"
       :db.install/_attribute :db.part/db}
      {:db/id #db/id[:db.part/db]
       :db/ident :pom/version
       :db/valueType :db.type/string
       :db/cardinality :db.cardinality/one
       :db/doc "version number from maven coordinates"
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
       :db/valueType :db.type/url
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
