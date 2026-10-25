"""Visible rows transcribed from dataset/evidence/images.

Each tuple is (filename, system_id, resource_id, category, extras).
extras uses the same result vocabulary as the JSON evidence.
Decoy rows that belong to a different email are included so they are not
folded into the neighboring subject.
"""

# category is a deletion_rules data_category.
# result: FOUND, NOT_FOUND, IDENTIFIABLE, ANONYMIZED, REDACTED, ACTIVE, DISABLED, BLOCKED

SHOTS = [
    (
        "account_admin_console_20260926.png",
        "account_service",
        "account_5762",
        "USER_PROFILE",
        {
            "result": "FOUND",
            "email": "haruka.s1838@zoho.com",
            "phone": "+81 90 7610 2507",
        },
    ),
    (
        "analytics_profile_view_20260713.png",
        "analytics_platform",
        "analytics_7438",
        "ANALYTICS_PROFILE",
        {
            "result": "IDENTIFIABLE",
            "email": "darwish.omar@icloud.com",
            "user_id": "user_20",
        },
    ),
    (
        "backup_restore_console_20260429.png",
        "backup_service",
        "backup_9287",
        "BACKUP_ARCHIVE",
        {"result": "ACTIVE", "email": "areed1433@gmail.com"},
    ),
    (
        "connector_management_console_20260807.png",
        "integration_service",
        "data_flow_1121",
        "DATA_FLOW",
        {"result": "ACTIVE", "email": "jain.aditi@gmail.com"},
    ),
    (
        "connector_management_console_20260807.png",
        "integration_service",
        "data_flow_9846",
        "DATA_FLOW",
        {"result": "ACTIVE", "email": "lucia-torres@gmail.com"},
    ),
    (
        "customer_export_console_20260618.png",
        "export_service",
        "export_1260",
        "USER_EXPORT",
        {"result": "FOUND", "email": "ingrid.dahl@outlook.com"},
    ),
    (
        "deleted_account_reference_20260310.png",
        "identity_service",
        "tombstone_17",
        "ACCOUNT_TOMBSTONE",
        {"result": "REDACTED", "user_id": "user_17"},
    ),
    (
        "marketing_profile_console.png",
        "marketing_platform",
        "marketing_001",
        "MARKETING_PROFILE",
        {
            "result": "FOUND",
            "email": "sj.park@naver.com",
            "phone": "+82 10-6837-9451",
        },
    ),
    (
        "search_index_inspector_20260901.png",
        "search_service",
        "search_428",
        "SEARCH_INDEX_ENTRY",
        {
            "result": "FOUND",
            "email": "g.silva76@gmail.com",
            "user_id": "user_13",
        },
    ),
    (
        "search_index_inspector_20260901.png",
        "search_service",
        "search_1874",
        "SEARCH_INDEX_ENTRY",
        {"result": "FOUND", "email": "g.silva76.jr@gmail.com"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_003",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03", "retention_until": "2027-08-25T04:03:00Z"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_002",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_001",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_006",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_005",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03"},
    ),
    (
        "security_audit_explorer_20260905.png",
        "security_service",
        "audit_record_004",
        "SECURITY_AUDIT_LOG",
        {"result": "FOUND", "user_id": "user_03"},
    ),
    (
        "support_ticket_console_20260524.png",
        "support_platform",
        "support_1034",
        "SUPPORT_MESSAGE",
        {
            "result": "IDENTIFIABLE",
            "email": "kagyeman8947@fastmail.com",
            "user_id": "user_22",
        },
    ),
]
