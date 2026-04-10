package authz

import rego.v1

default allow := false

deny contains "archived_non_admin" if {
    input.resource.archived
    input.user.role != "admin"
}

deny contains "contractor_read_only" if {
    input.user.role == "contractor"
    input.action != "read"
}

deny contains "team_boundary_non_admin" if {
    input.user.team != input.resource.owner_team
    input.resource.visibility != "public"
    input.user.role != "admin"
}

deny contains "delete_requires_admin" if {
    input.action == "delete"
    input.user.role != "admin"
}

deny contains "unauthenticated_sensitive" if {
    not input.user.is_authenticated
    input.resource.sensitivity > 0
    input.user.role != "admin"
}

allow if {
    count(deny) == 0
}
