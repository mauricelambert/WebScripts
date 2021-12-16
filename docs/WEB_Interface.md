# WEB Interface

## Custom interface

 - The index page path should be `static/templates/index.html` of the current directory, if not exist the default file will be used.
 - The script page path should be `static/templates/script.html` of the current directory, if not exist the default file will be used.

## Static and JS paths

The static and JS paths are configured, you can change the configurations. Be careful with informations in static files because there is no authentication for these files.

 - `js_path`: a list of glob syntax to get javascript files.
 - `statics_path`: a list of glob syntax to get files (HTML, JPG, PDF, CSS, or other).

## URLs

The URL to get javascript files is: `/js/<filename>`.
With the default install on *localhost:8000*, you can request three files:

 - http://127.0.0.1:8000/js/webscripts_script_js_scripts.js
 - http://127.0.0.1:8000/js/webscripts_index_js_scripts.js
 - http://127.0.0.1:8000/js/webscripts_js_scripts.js

The URL to get static files is: `/static/<filename>`.
With the default install on *localhost:8000*, you can request sixteen files:

 - http://127.0.0.1:8000/static/index.html
 - http://127.0.0.1:8000/static/commons.html
 - http://127.0.0.1:8000/static/Errors.html
 - http://127.0.0.1:8000/static/Pages.html
 - http://127.0.0.1:8000/static/utils.html
 - http://127.0.0.1:8000/static/WebScripts.html
 - http://127.0.0.1:8000/static/manage_defaults_databases.html
 - http://127.0.0.1:8000/static/uploads_management.html
 - http://127.0.0.1:8000/static/requests_management.html
 - http://127.0.0.1:8000/static/error_pages.html
 - http://127.0.0.1:8000/static/csp.html
 - http://127.0.0.1:8000/static/share.html
 - http://127.0.0.1:8000/static/webscripts_index_style.css
 - http://127.0.0.1:8000/static/webscripts_script_style.css
 - http://127.0.0.1:8000/static/webscripts_style.css
 - http://127.0.0.1:8000/static/webscripts_header.jpg
 - http://127.0.0.1:8000/static/webscripts_icon.jpg

To customize these files, you can create files with the same relative path and name from the current directory.

## Icons and images

Images and icons are static files:

Create a file with this path and name to replace the default icon:

 - `static/images/webscripts_icon.jpg`

Create a file with this path and name to replace the default image (on the top right of the interface):

 - `static/images/webscripts_header.jpg`
