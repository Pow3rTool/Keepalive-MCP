"""Shared test configuration seeded before importing the runtime module."""
import os


os.environ.update({
    "KA_DB_DSN":             "postgresql://u:p@localhost:5432/ka",
    "KA_TENANT_ID":          "00000000-0000-0000-0000-000000000000",
    "KA_CLIENT_ID":          "11111111-1111-1111-1111-111111111111",
    "KA_REQUIRED_SCOPE":     "user_impersonation",
    "KA_ALLOWED_CLIENTS":    "22222222-2222-2222-2222-222222222222",
    "KA_REDIRECT_URI":       "https://ka.example.com/auth/callback",
    "KA_SSH_HOSTKEY_POLICY": "off",
    "KA_SSH_PASSWORD":       "dummy",
    "KA_FILTER_TOOL_LIST":   "true",
})
