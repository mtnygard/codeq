(ns datomic.codeq.analyzers.pom
  (:require [datomic.api :as d]
            [datomic.codeq.util :refer [cond-> index->id-fn tempid?]]
            [datomic.codeq.analyzer :as az]
            [clj-xpath.core :as x]
            [clojure.pprint :refer [pprint]]))

(defn maybe-new-codeq
  [db f ret contents loc sha->id added]
  (let [sha       (-> contents az/ws-minify az/sha)
        codeid    (sha->id sha)
        newcodeid (and (tempid? codeid) (not (added codeid)))
        ret       (cond-> ret newcodeid (conj {:db/id codeid :code/sha sha :code/text contents}))
        added     (cond-> added newcodeid (conj codeid))

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
    [ret codeqid added]))

(defn xpath->attribute
  [path attribute db f dom ret {:keys [sha->id added] :as ctx}]
  (if-let [node (first (x/$x path dom))]
    (let [contents            (:text node)
          [ret codeqid added] (maybe-new-codeq db f ret contents path sha->id added)
          ret                 (conj ret [:db/add f attribute contents])]
      [ret (assoc ctx :added added)])
    [ret ctx]))

(defn find-depid
  [db group artifact version]
  (ffirst (d/q '[:find ?d
                 :in $ ?g ?a ?v
                 :where [?d :pom/group ?g]
                        [?d :pom/artifact ?a]
                        [?d :pom/version ?v]]
               db group artifact version)))

(defn maybe-new-depid
  [db {:keys [groupId artifactId version]}]
  (or (find-depid db groupId artifactId version)
      (d/tempid :db.part/user)))

(defn child-with-tag
  [n t]
  (first (filter #(= t (:tag %)) @(:children n))))

(defn dom->dep
  [node]
  (if-let [children @(:children node)]
    (let [xtr     (fn [m k]
                    (if (child-with-tag node k) (assoc m k (:text (child-with-tag node k))) m))
          m       {:content (:text node)
                   :path    (str "/project/dependencies[artifactId=\"" (:text (child-with-tag node :artifactId)) "\"]")}
          m       (xtr m :groupId)
          m       (xtr m :artifactId)
          m       (xtr m :version)]
      m)))

(defn dom->dependencies
  [dom]
  (map dom->dep (x/$x "/project/dependencies/*" dom)))

(defn dependencies
  [db f dom ret {:keys [sha->id] :as ctx}]
  (loop [ret ret, ctx ctx, deps (dom->dependencies dom)]
    (if-let [{:keys [path content groupId artifactId version] :as d} (first deps)]
      (let [added               (:added ctx)
            [ret codeqid added] (maybe-new-codeq db f ret content path sha->id added)
            depid               (maybe-new-depid db d)

            ret                 (cond-> ret
                                        (tempid? depid)
                                        (conj {:db/id depid
                                               :pom/group groupId
                                               :pom/artifact artifactId
                                               :pom/version version})

                                        (or (tempid? depid) (added depid))
                                        (conj [:db/add f :pom/dependency depid]))
            
            added               (cond-> added
                                        (tempid? depid)
                                        (conj depid))
            ctx                 (assoc ctx :added added)]
        (recur ret ctx (rest deps)))
      [ret ctx])))

(def fragments [(partial xpath->attribute "/project/artifactId"  :pom/artifact)
                (partial xpath->attribute "/project/groupId"     :pom/group)
                (partial xpath->attribute "/project/name"        :pom/name)
                (partial xpath->attribute "/project/version"     :pom/version)
                (partial xpath->attribute "/project/description" :pom/description)
                dependencies])

(defn analyze
  [db f src]
  (let [dom (x/xml->doc src)
        ctx {:sha->id  (index->id-fn db :code/sha)
             :name->id (index->id-fn db :code/name)
             :added    #{}}]
    (loop [ret [], ctx ctx, frags fragments]
      (if-let [frag (first frags)]
        (let [[ret ctx] (frag db f dom ret ctx)]
          (recur ret ctx (rest frags)))
        ret))))

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
;; clear analysis for re-run
(let [db (d/db conn)]
  (let [eavts (d/q '[:find ?tx ?a ?v :where [?tx :tx/analyzer :pom]] db)]
    (d/transact conn (map #(vector ':db/retract (first %) ':tx/analyzer ':pom) eavts))
    (d/transact conn (map #(vector ':db/retract (first %) ':tx/analyzerRev 1) eavts)))
  (doseq [[dp] (d/q '[:find ?d :where [?d :pom/group]] db)]
    (d/transact conn [[:db.fn/retractEntity dp]])))

(def uri "datomic:mem://git")
(def uri "datomic:free://localhost:4334/codeq")
(def conn (d/connect uri))
(def db (d/db conn))
(d/q '[:find ?e :where [?f :file/name "pom.xml"] [?n :node/filename ?f] [?n :node/object ?e]] db)
(d/q '[:find ?e :where [?e :pom/dependency]] db)

(d/q '[:find ?d :in $ ?g ?a ?v :where [?d :pom/group ?g] [?d :pom/artifact ?a] [?d :pom/version ?v]] db "org.codehaus.jsr166-mirror" "jsr166y" "1.7.0")

(find-depid db "org.codehaus.jsr166-mirror" "jsr166y" "1.7.0")

(sort (d/q '[:find ?name ?dep :where [?e :pom/name ?name] [?e :pom/dependency ?dep]] db))

(sort (d/q '[:find ?name ?g ?a ?v :where [?e :pom/name ?name] [?e :pom/dependency ?dep] [?dep :pom/group ?g] [?dep :pom/artifact ?a] [?dep :pom/version ?v]] db))

)
