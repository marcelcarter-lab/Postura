"""Known static file/folder paths that reveal which CMS platform a
site is running, if present. Each entry maps a path to (CMS name,
confidence) — some paths are near-certain signals (e.g. wp-login.php
is WordPress-specific), while others are weaker/more generic and
could theoretically coincide with an unrelated setup."""

CMS_SIGNATURE_PATHS = {
    "wp-content/": ("WordPress", "high"),
    "wp-includes/": ("WordPress", "high"),
    "wp-login.php": ("WordPress", "high"),
    "sites/default/": ("Drupal", "possible"),
    "sites/default/settings.php": ("Drupal", "high"),
    "administrator/": ("Joomla", "possible"),
    "components/com_content/": ("Joomla", "high"),
    "typo3conf/": ("TYPO3", "high"),
    "craft/": ("Craft CMS", "possible"),
    "umbraco/": ("Umbraco", "high"),
}
