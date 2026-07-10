"""Curated list of sensitive paths commonly left accidentally exposed
on misconfigured web servers. Grouped by category for readability and
easier future maintenance (e.g. extending one category without
scrolling through an undifferentiated flat list).

Each entry is a relative path appended to the target's base URL.
"""

VCS_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/HEAD",
    ".svn/entries",
    ".hg/store/00manifest.i",
]

ENV_AND_CONFIG_PATHS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    "config.php",
    "config.php.bak",
    "wp-config.php",
    "wp-config.php.bak",
    "configuration.php",
    "settings.py",
    "config.yml",
    "config.yaml",
    "appsettings.json",
    "phpinfo.php",
    "info.php",
]

BACKUP_AND_ARCHIVE_PATHS = [
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.sql.gz",
    "database.sql",
    "db_backup.sql",
    "site-backup.zip",
    "www.zip",
    "www.tar.gz",
    "index.php.bak",
    "index.html.bak",
    ".DS_Store",
]

# The full list used by the exposure scanner. Order is preserved
# roughly by risk severity (VCS exposure and .env leaks are typically
# more severe than a stray .DS_Store), though the scanner itself
# should assign severity per-finding rather than relying on list order.
EXPOSURE_WORDLIST = VCS_PATHS + ENV_AND_CONFIG_PATHS + BACKUP_AND_ARCHIVE_PATHS
