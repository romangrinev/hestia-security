---
mode: agent
description: Review Laravel and Livewire upload validation and storage boundaries
---

Review the application's upload flow using its actual installed framework
versions, fields, and deployment process. Make changes in the application
repository and deliver them through its existing tested deployment workflow.
Do not put production domains, credentials, logs, or incident evidence in this
public toolkit.

1. Inventory public and authenticated upload fields and their required formats.
   Livewire's temporary upload endpoint is shared by those fields. Restrict
   `temporary_file_upload.rules` by actual file content, original filename
   extension, and size before temporary storage; size-only validation is not
   sufficient. Keep the allowed formats needed by administrative forms.
2. Apply field-specific validation again before permanent storage. HTML
   `accept`, CAPTCHA, User-Agent and Referer filters are not server-side file
   validation. Inspect the actual server validation used by UI components.
3. Keep temporary uploads outside the public document root. Check the resolved
   filesystem disk root and all public symlinks, not just the disk's name.
4. Verify that the web server cannot execute scripts in upload directories,
   including mixed-case suffixes and PATH_INFO variants. Nginx does not read
   `.htaccess`; use the appropriate nginx configuration and test it before reload.
5. Check locked and installed dependency versions and current security advisories.
   Update compatible dependencies in the repository and run the application tests.
6. Test the temporary HTTP endpoint directly with harmless fixtures: mixed-case
   script extensions, valid image bytes with a script filename, invalid content
   with an allowed filename, an unsafe file in a batch, oversized files, and
   permitted formats. Assert rejected files never reach temporary storage.
7. Verify the deployed commit and effective cached rules. Do not submit real
   customer forms or execute uploaded PHP during verification.

Preserve any suspicious files and their original metadata in a restricted
incident directory outside the served tree. A file's presence or timestamp
does not by itself establish its entry point, execution, or creation time.
