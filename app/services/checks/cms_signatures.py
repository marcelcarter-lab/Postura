"""Known static file/folder paths that reveal which CMS platform a
site is running, if present. Each entry maps a path to the CMS it
signals — presence of any of these is itself the finding (this is
fingerprinting, not a vulnerability check)."""

CMS_SIGNATURE_PATHS = {
    "wp-content/": "WordPress",
    "wp-includes/": "WordPress",
    "wp-login.php": "WordPress",
    "sites/default/": "Drupal",
    "sites/default/settings.php": "Drupal",
    "administrator/": "Joomla",
    "components/com_content/": "Joomla",
    "typo3conf/": "TYPO3",
    "craft/": "Craft CMS",
    "umbraco/": "Umbraco",
}
