"""Browser signature knowledge base.

Encodes the six AI agent browsers analysed in the paper: their identifying
local traces, the agent artifacts they produce (paper Table 6 and Section 4.1),
the service-type classification (Table 4 / Section 5.2), and the API endpoints
used for reconstruction (Section 4.1, for the later collection module).

Path notes
----------
* ``{profile}`` is a placeholder for a Chromium profile directory (Default,
  Profile 1, ...). The path resolver expands it by globbing.
* Paths use forward slashes; the resolver matches components case-insensitively
  so they work on live Windows and on forensic images analysed elsewhere.
"""

from __future__ import annotations

from .models import (
    Anchor,
    ApiEndpoint,
    ArtifactSpec,
    BrowserSignature,
    Category,
    IdentMarker,
    Presence,
    ServiceType,
)

# Fixed extension IDs of the built-in agent extensions (paper Table 6).
EXT_BROWSEROS = "bflpfmnmnokmjhmgnolecpppdbdophmk"
EXT_SIGMA = "amabiocpfnlgbceffljgkcjeacejflga"


# ---------------------------------------------------------------------------
# Comet (Perplexity) — local-centric. All four categories cached locally.
# ---------------------------------------------------------------------------
COMET = BrowserSignature(
    key="comet",
    name="Comet",
    developer="Perplexity AI Inc.",
    base_arch="Chromium",
    service_type=ServiceType.LOCAL,
    user_data_anchor=Anchor.LOCAL,
    user_data_relpath="Perplexity/Comet/UserData",
    extension_id=None,
    auth_summary=(
        "NextAuth encrypted session cookie (JWE) '__Secure-next-auth.session-token' "
        "in Network/Cookies; Local Storage key 'pplx-next-auth-session' exposes "
        "email/name/UUID/expiry in plaintext."
    ),
    markers=(
        IdentMarker("install_dir", Anchor.LOCAL, "Perplexity/Comet/UserData", 0.7,
                    "Comet UserData directory"),
        IdentMarker("support_dir", Anchor.LOCAL,
                    "Perplexity/Comet/UserData/{profile}/Local Storage/leveldb", 0.3,
                    "Comet Local Storage (LevelDB)"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.ACCOUNT, Anchor.LOCAL,
            "Perplexity/Comet/UserData/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "pplx-next-auth-session (email/name/username/UUID/expiry), "
            "comet-sidecar-threads-by-id (conv URL slug+time), pplx-top-sites-cache.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.PROMPT, Anchor.LOCAL,
            "Perplexity/Comet/UserData/{profile}/IndexedDB/https_www.perplexity.ai_0.indexeddb.leveldb",
            "*.ldb;*.log", "IndexedDB (keyval-store)",
            "Cached REST responses keyed by endpoint: /rest/thread/list_recent "
            "(titles=prompts, uuid, status); thread_metadata/all_results hold "
            "query_str (prompt).",
            Presence.BOTH,
            note="Entries carry expiry_time (~30 days); older convs may be evicted.",
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.LOCAL,
            "Perplexity/Comet/UserData/{profile}/IndexedDB/https_www.perplexity.ai_0.indexeddb.leveldb",
            "*.ldb;*.log", "IndexedDB (keyval-store)",
            "workflow_block (execution steps, search queries, referenced sources) "
            "inside cached thread bodies.",
            Presence.BOTH,
        ),
        ArtifactSpec(
            Category.OUTPUT, Anchor.LOCAL,
            "Perplexity/Comet/UserData/{profile}/IndexedDB/https_www.perplexity.ai_0.indexeddb.leveldb",
            "*.ldb;*.log", "IndexedDB (keyval-store)",
            "markdown_block.answer (agent response), model used, timestamps, "
            "author_id/author_username (attribution).",
            Presence.BOTH,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "Perplexity/Comet/UserData/{profile}/Network",
            "Cookies", "Cookies (SQLite)",
            "__Secure-next-auth.session-token (JWE) for API reconstruction.",
            Presence.LOCAL, encrypted=True,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL, "Perplexity/Comet/UserData",
            "Local State", "Local State (JSON)",
            "os_crypt.encrypted_key (DPAPI-wrapped AES key) — decrypts v10 cookies.",
            Presence.LOCAL, encrypted=True,
            note="Master key for cookie/login decryption.",
        ),
    ),
    endpoints=(
        ApiEndpoint("/rest/thread/list_recent", "GET",
                    "conversation list (titles=prompts, uuid, slug, status)",
                    "session cookie", 1),
        ApiEndpoint("/rest/thread/<slug>", "GET",
                    "full conversation body (prompts, responses, sources, email)",
                    "session cookie", 2),
        ApiEndpoint("/rest/user/settings", "GET",
                    "subscription tier, query usage, connectors",
                    "session cookie", 3),
    ),
)


# ---------------------------------------------------------------------------
# Fellou (ASI X) — Electron, cloud-centric. Only account/tokens local.
# ---------------------------------------------------------------------------
FELLOU = BrowserSignature(
    key="fellou",
    name="Fellou",
    developer="ASI X Inc.",
    base_arch="Electron",
    service_type=ServiceType.CLOUD,
    user_data_anchor=Anchor.ROAMING,
    user_data_relpath="Fellou",
    extension_id=None,
    auth_summary=(
        "fellou.id_token (JWT issued by Authing, fellou.us.authing.co/oidc) sent as "
        "Authorization: Bearer. Base64-decodes to userID/name/email/picture; "
        "expiry ~10 years after issuance — long recovery window."
    ),
    markers=(
        IdentMarker("install_dir", Anchor.ROAMING, "Fellou/FellouUserData", 0.6,
                    "Fellou user/profile metadata directory"),
        IdentMarker("support_dir", Anchor.ROAMING, "Fellou/Partitions", 0.4,
                    "Fellou Partitions (per-user/profile storage)"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.ACCOUNT, Anchor.ROAMING, "Fellou/FellouUserData",
            "user.json;currentUser.json;metaInfo.json;metadata.json",
            "JSON / SQLite",
            "All user metadata: user ID, profile ID, creation time, last login; "
            "currently active user.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.ROAMING,
            "Fellou/FellouUserData/{folder16}/profiles/{profile}",
            "sqliteDatabase.db", "SQLite",
            "Visited URL, visit time/count, and visit method (ai/human) — "
            "distinguishes agent autonomous browsing from user browsing.",
            Presence.LOCAL,
            note="Browsing traces only; prompts/workflow bodies are server-side.",
        ),
        ArtifactSpec(
            Category.ACCOUNT, Anchor.ROAMING,
            "Fellou/Partitions/shared-process/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "Account info (name, email, phone, creation time) + login and "
            "API-request authentication tokens.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.ROAMING,
            "Fellou/Partitions/profile-{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "fellou.id_token and related authentication tokens.",
            Presence.LOCAL,
        ),
    ),
    endpoints=(
        ApiEndpoint("/api/userPoint", "GET",
                    "account identifiers (userID, name, email, createdAt, planType)",
                    "Bearer fellou.id_token", 1),
        ApiEndpoint("/api/chat/history", "GET",
                    "conversation list: chatId, title, time, first_message.content (prompt)",
                    "Bearer fellou.id_token", 2),
        ApiEndpoint("/api/chat/message/<chatId>", "GET",
                    "prompts, tool-invocation records, full agent workflow",
                    "Bearer fellou.id_token", 3),
        ApiEndpoint("/api/task-config/scheduled-task", "GET",
                    "registered scheduled/automated tasks (intent clues)",
                    "Bearer fellou.id_token", 4),
    ),
)


# ---------------------------------------------------------------------------
# Microsoft Edge (Copilot) — cloud-centric. Only encrypted MSAL tokens local.
# ---------------------------------------------------------------------------
EDGE = BrowserSignature(
    key="edge",
    name="Microsoft Edge (Copilot)",
    developer="Microsoft",
    base_arch="Chromium",
    service_type=ServiceType.CLOUD,
    user_data_anchor=Anchor.LOCAL,
    user_data_relpath="Microsoft/Edge/User Data",
    extension_id=None,
    auth_summary=(
        "Copilot authenticates with an MSAL-issued Bearer (JWT) token. Local "
        "Storage holds msal.2.* cache and token.keys (ID/access token scopes, "
        "tenant/user/client IDs); the token body itself is DPAPI-encrypted."
    ),
    markers=(
        # Edge ships on every Windows install, so presence alone is weak evidence
        # of *Copilot agent usage*. Confirming Copilot use requires inspecting the
        # MSAL cache (msal.2.* keys) during parsing — see note.
        IdentMarker("install_dir", Anchor.LOCAL, "Microsoft/Edge/User Data", 0.4,
                    "Edge User Data directory (Edge is preinstalled on Windows)"),
        IdentMarker("support_dir", Anchor.LOCAL,
                    "Microsoft/Edge/User Data/{profile}/Local Storage/leveldb", 0.6,
                    "Edge Local Storage (LevelDB) — check for msal.2.* Copilot cache"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "Microsoft/Edge/User Data/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "MSAL cache (msal.2.* keys, token.keys): ID/access token scopes, "
            "tenant/user/client IDs, session id, nonce, lastUpdatedAt.",
            Presence.LOCAL, encrypted=True,
            note="Token body is DPAPI-encrypted; decrypt under the same user account.",
        ),
        ArtifactSpec(
            Category.ACCOUNT, Anchor.LOCAL,
            "Microsoft/Edge/User Data/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "Tenant/user/client identifiers from token.keys (session metadata).",
            Presence.LOCAL, encrypted=True,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL, "Microsoft/Edge/User Data",
            "Local State", "Local State (JSON)",
            "os_crypt.encrypted_key (DPAPI-wrapped AES key) — decrypts v10 "
            "cookies/login data (MSAL token body is DPAPI, separate).",
            Presence.LOCAL, encrypted=True,
            note="Master key for cookie/login decryption.",
        ),
    ),
    endpoints=(
        ApiEndpoint("copilot.microsoft.com/c/api/conversations", "GET",
                    "conversation list: conversationId, title, last-activity time",
                    "Bearer MSAL JWE", 1),
        ApiEndpoint("copilot.microsoft.com/c/api/conversations/<conversationId>/history",
                    "GET",
                    "conversation body: prompts, responses, author (human/ai), "
                    "time, citations (title/url)",
                    "Bearer MSAL JWE; conversationId", 2),
    ),
)


# ---------------------------------------------------------------------------
# BrowserOS — local-centric, agent is a built-in Chrome extension (fixed ID).
# No separate login feature, so Account is N/A.
# ---------------------------------------------------------------------------
BROWSEROS = BrowserSignature(
    key="browseros",
    name="BrowserOS",
    developer="BrowserOS Software",
    base_arch="Chromium",
    service_type=ServiceType.LOCAL,
    user_data_anchor=Anchor.LOCAL,
    # Real install: %LocalAppData%\BrowserOS\BrowserOS\User Data (Chromium-std
    # "User Data"; the paper's table wrote "UserData"/"BrowserOS\UserData" with a
    # level dropped — corrected here against the live build).
    user_data_relpath="BrowserOS/BrowserOS/User Data",
    extension_id=EXT_BROWSEROS,
    auth_summary=(
        "Cloud graphql uses the '__Secure-better-auth.session_token' cookie "
        "(Network/Cookies, DPAPI-encrypted on disk). A local agent control "
        "server also runs on loopback 127.0.0.1 (not proxy-capturable; external "
        "requests 403 by Origin). Google OAuth bound session + device identifier "
        "also present in Cookies/Login Data."
    ),
    markers=(
        # Install dir is the reliable signal; the extension store only exists
        # after the agent is used, so it is a confirming (not required) marker.
        IdentMarker("install_dir", Anchor.LOCAL, "BrowserOS/BrowserOS/User Data", 0.6,
                    "BrowserOS User Data directory"),
        IdentMarker("extension", Anchor.LOCAL,
                    f"BrowserOS/BrowserOS/User Data/{{profile}}/Local Extension Settings/{EXT_BROWSEROS}",
                    0.4, f"BrowserOS agent extension ({EXT_BROWSEROS})"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.PROMPT, Anchor.LOCAL,
            f"BrowserOS/BrowserOS/User Data/{{profile}}/Local Extension Settings/{EXT_BROWSEROS}",
            "*.ldb;*.log", "Local Extension Settings (LevelDB)",
            "Per-conversation UUID, lastMessagedAt, user prompts.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.LOCAL,
            f"BrowserOS/BrowserOS/User Data/{{profile}}/Local Extension Settings/{EXT_BROWSEROS}",
            "*.ldb;*.log", "Local Extension Settings (LevelDB)",
            "Agent reasoning and tool-invocation inputs/outputs, step by step.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.OUTPUT, Anchor.LOCAL,
            f"BrowserOS/BrowserOS/User Data/{{profile}}/Local Extension Settings/{EXT_BROWSEROS}",
            "*.ldb;*.log", "Local Extension Settings (LevelDB)",
            "Tool outputs / agent results stored alongside the workflow.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.LOCAL,
            f"BrowserOS/BrowserOS/User Data/{{profile}}/IndexedDB",
            f"chrome-extension_{EXT_BROWSEROS}_0.indexeddb.leveldb",
            "IndexedDB (LevelDB)",
            "Agent extension IndexedDB store (conversation/workflow records).",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.LOCAL,
            "BrowserOS/BrowserOS/User Data/.browseros",
            "browseros-server.log;browseros-server.log.old", "Server log",
            "Service startup, tool loading, per-conv conversationId + model, "
            "processing flow from chat request to completion (timestamped).",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.OUTPUT, Anchor.LOCAL,
            "BrowserOS/BrowserOS/User Data/.browseros",
            "browseros.db;browseros.db-wal;browseros.db-shm", "SQLite",
            "Server-side agent state DB (conversations, runs) maintained by the "
            "local BrowserOS control server.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.TEMP, ".",
            "gemini-client-error-*.json", "Temp (LLM error dump)",
            "On LLM call failure: conversation context + function-call sequence.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "BrowserOS/BrowserOS/User Data/{profile}/Network",
            "Cookies;Login Data", "Cookies / Login Data (SQLite)",
            "__Secure-better-auth.session_token (graphql), Google OAuth session, "
            "device identifier, login info.",
            Presence.LOCAL, encrypted=True,
            note="Secrets DPAPI-protected; decrypt via Local State key.",
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL, "BrowserOS/BrowserOS/User Data",
            "Local State", "Local State (JSON)",
            "os_crypt.encrypted_key (DPAPI-wrapped AES key) — decrypts v10 cookies "
            "incl. __Secure-better-auth.session_token.",
            Presence.LOCAL, encrypted=True,
            note="Master key for cookie/login decryption.",
        ),
    ),
    endpoints=(
        ApiEndpoint("https://api.browseros.com/graphql", "POST",
                    "GetConversationWithMessages(conversationId) -> "
                    "conversationMessages.nodes.message (full conversation body)",
                    "Cookie __Secure-better-auth.session_token", 1),
        ApiEndpoint("http://127.0.0.1/<chat|mcp|agents>", "POST",
                    "local agent control (CDP, tool execution, session) — "
                    "loopback only, Origin-restricted",
                    "loopback", 2),
    ),
)


# ---------------------------------------------------------------------------
# Sigma — hybrid, agent is a bundled extension (fixed ID). Workflow server-only.
# ---------------------------------------------------------------------------
SIGMA = BrowserSignature(
    key="sigma",
    name="Sigma Browser",
    developer="Sigmabrowser",
    base_arch="Chromium",
    service_type=ServiceType.HYBRID,
    user_data_anchor=Anchor.LOCAL,
    # Per the paper (Section 4.1.5): %LocalAppData%\Chromium\UserData{Profile}.
    user_data_relpath="Chromium/UserData",
    extension_id=EXT_SIGMA,
    auth_summary=(
        "JWT access_token (server: bagoodex.io) sent as Authorization: Bearer. "
        "Stored in Local Storage 'search-storage' and in the extension's "
        "chrome.storage.local 'socketAuth' (sessionId/token). Token payload "
        "embeds sub_user_id and session_id."
    ),
    markers=(
        # The Chromium\UserData install dir is the reliable identifier; the agent
        # extension is bundled as a .crx and only writes Local Extension Settings
        # after the agent is used, so it is a confirming (not required) marker.
        IdentMarker("install_dir", Anchor.LOCAL, "Chromium/UserData", 0.7,
                    "Sigma UserData directory (Chromium\\UserData)"),
        IdentMarker("extension", Anchor.LOCAL,
                    f"Chromium/UserData/{{profile}}/Local Extension Settings/{EXT_SIGMA}",
                    0.3, f"Sigma agent extension ({EXT_SIGMA})"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.ACCOUNT, Anchor.LOCAL,
            "Chromium/UserData/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "search-storage.state.user: userId, email, username, profile image, "
            "created_at, last_login_at, plan, usage limits; access_token, "
            "refresh_token, session_id, is_log_in.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.PROMPT, Anchor.LOCAL,
            "Chromium/UserData/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "state.userHistory[]: taskId, time, query (prompt), thread_name, "
            "task type (web-agent), and search hash (== /api/v1/search search_hash).",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.PROMPT, Anchor.LOCAL,
            f"Chromium/UserData/{{profile}}/Local Extension Settings/{EXT_SIGMA}",
            "*.ldb;*.log", "Local Extension Settings (LevelDB)",
            "userId, socketAuth (sessionId/access_token), the raw text typed into "
            "the input box (original prompt), lastVisitedPath, activeTarget_<uuid>.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.OUTPUT, Anchor.LOCAL,
            "Chromium/UserData/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "Agent answers cached locally.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.WORKFLOW, Anchor.LOCAL,
            "Chromium/UserData/{profile}/Local Storage/leveldb",
            "*.ldb;*.log", "Local Storage (LevelDB)",
            "Agent step-by-step reasoning is NOT stored locally — fetch via "
            "/api/v1/search using the search hash.",
            Presence.SERVER,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "Chromium/UserData/{profile}/Network",
            "Cookies", "Cookies (SQLite)",
            "Authentication token (for reissue).",
            Presence.LOCAL, encrypted=True,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL, "Chromium/UserData",
            "Local State", "Local State (JSON)",
            "os_crypt.encrypted_key (DPAPI-wrapped AES key) — decrypts v10 cookies.",
            Presence.LOCAL, encrypted=True,
            note="Master key for cookie/login decryption.",
        ),
    ),
    endpoints=(
        ApiEndpoint("/api/v1/account/profile", "GET",
                    "userId, email, username, created/last-login, plan, usage limits",
                    "Bearer access_token", 1),
        ApiEndpoint("/api/v1/account/thread/history/<user_id>", "GET",
                    "task history: id, time, query, hash, sessionId, type, name, summary",
                    "Bearer access_token", 2),
        ApiEndpoint("/api/v1/search", "POST",
                    "detailed task: agent step-by-step execution log (workflow)",
                    "Bearer access_token; body search_hash", 3),
    ),
)


# ---------------------------------------------------------------------------
# Genspark (MainFunc) — cloud-centric. One API call returns everything.
# ---------------------------------------------------------------------------
GENSPARK = BrowserSignature(
    key="genspark",
    name="Genspark Browser",
    developer="MainFunc Inc.",
    base_arch="Chromium",
    service_type=ServiceType.CLOUD,
    user_data_anchor=Anchor.LOCAL,
    user_data_relpath="GensparkSoftware/Genspark-Browser/UserData",
    extension_id=None,
    auth_summary=(
        "Cookie-based auth: session_id, ai_user (user id + first-issue time), "
        "ai_session (session timestamp) in Network/Cookies, plaintext. IndexedDB "
        "holds a reissue authentication token."
    ),
    markers=(
        IdentMarker("install_dir", Anchor.LOCAL,
                    "GensparkSoftware/Genspark-Browser/UserData", 0.7,
                    "Genspark UserData directory"),
        IdentMarker("support_dir", Anchor.LOCAL,
                    "GensparkSoftware/Genspark-Browser/UserData/{profile}/Network", 0.3,
                    "Genspark Network (session cookies)"),
    ),
    artifacts=(
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "GensparkSoftware/Genspark-Browser/UserData/{profile}/IndexedDB",
            "https_*.indexeddb.leveldb", "IndexedDB (LevelDB)",
            "Reissue authentication token.",
            Presence.LOCAL,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "GensparkSoftware/Genspark-Browser/UserData/{profile}/Network",
            "Cookies", "Cookies (SQLite)",
            "session_id (=auth token), ai_user (user id + first-issue time), "
            "ai_session (session timestamp) — account + activity timing.",
            Presence.LOCAL, encrypted=True,
        ),
        ArtifactSpec(
            Category.ACCOUNT, Anchor.LOCAL,
            "GensparkSoftware/Genspark-Browser/UserData/{profile}",
            "Login Data", "Login Data (SQLite)",
            "Account info (email).",
            Presence.LOCAL, encrypted=True,
        ),
        ArtifactSpec(
            Category.AUTH, Anchor.LOCAL,
            "GensparkSoftware/Genspark-Browser/UserData",
            "Local State", "Local State (JSON)",
            "os_crypt.encrypted_key (DPAPI-wrapped AES key) — decrypts the v10 "
            "session_id cookie (the auth token).",
            Presence.LOCAL, encrypted=True,
            note="Master key for cookie/login decryption.",
        ),
    ),
    endpoints=(
        ApiEndpoint("/api/project/my", "GET",
                    "ALL projects (conversations): first_message_of_user (prompt), "
                    "user_message, project_memory_summary, output_digest, "
                    "session_clean_text (full per-round flow → prompt+workflow+output)",
                    "cookies", 1),
        ApiEndpoint("/api/user", "GET",
                    "account + subscription: id, display name, profile URL, email",
                    "cookies", 2),
    ),
)


# Registry --------------------------------------------------------------------
SIGNATURES: tuple[BrowserSignature, ...] = (
    COMET, FELLOU, EDGE, BROWSEROS, SIGMA, GENSPARK,
)

BY_KEY: dict[str, BrowserSignature] = {s.key: s for s in SIGNATURES}


def get(key: str) -> BrowserSignature:
    return BY_KEY[key]
