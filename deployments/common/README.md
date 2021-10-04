Extend the Kubernetes API with CustomResourceDefinitions
========================================================

We create a new CustomResourceDefinition (CRD), the Kubernetes API Server
creates a new RESTful resource path for each version you specify. The CRD can be
either namespaced or cluster-scoped, as specified in the CRD's scope field. As
with existing built-in objects, deleting a namespace deletes all custom objects
in that namespace. CustomResourceDefinitions themselves are non-namespaced and
are available to all namespaces.
