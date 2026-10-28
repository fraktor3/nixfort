"""Static files with content hashes in their names (app.3f9c2a.css): after an update the browser
loads new CSS and JS at once, without a hard refresh or a private window."""

from django.contrib.staticfiles.storage import ManifestStaticFilesStorage


class HashedStaticStorage(ManifestStaticFilesStorage):
    # Only CSS references are rewritten (fonts in url(), @import). Source-map comments of vendored
    # scripts are left alone, so a missing .map file never breaks collectstatic.
    patterns = (
        (
            "*.css",
            (
                r"""(?P<matched>url\(['"]{0,1}\s*(?P<url>.*?)["']{0,1}\))""",
                (r"""(?P<matched>@import\s*["']\s*(?P<url>.*?)["'])""", """@import url("%(url)s")"""),
            ),
        ),
    )
    # A file missing from the manifest is served under its plain name instead of failing the page.
    manifest_strict = False
