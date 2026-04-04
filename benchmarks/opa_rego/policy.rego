package authz

import rego.v1

default allow := false

allow if {
    input.user.role == "admin"
    not input.resource.archived
}

deny contains "archived_read_only" if {
    input.resource.archived
    input.action != "read"
}

deny contains "contractor_read_only" if {
    input.user.role == "contractor"
    input.action != "read"
}

deny contains "team_boundary" if {
    input.user.team != input.resource.owner_team
    input.resource.visibility != "public"
}

deny contains "minimum_role_write" if {
    input.action == "write"
    input.user.role_level < 1
}

deny contains "minimum_role_delete" if {
    input.action == "delete"
    input.user.role_level < 2
}

deny contains "brute_force" if {
    input.context.failed_attempts > 5
    input.context.concurrent_sessions > 3
}

deny contains "risk_score_exceeded" if {
    risk := input.context.failed_attempts * 2 + input.context.concurrent_sessions * 3
    risk > 15
}

deny contains "off_hours_sensitive" if {
    input.user.role != "admin"
    input.resource.sensitivity > 1
    not input.context.is_business_hours
}

deny contains "unauthenticated_sensitive" if {
    not input.user.is_authenticated
    input.resource.sensitivity > 0
}

allow if {
    count(deny) == 0
    input.user.role != "admin"
}
