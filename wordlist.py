# based on:
# - onelistforallmicro.txt
# - http://github.com/bo0om/fuzz.txt
# validate words with:
#     google dorks -> inurl:"<WORD>" intitle:"index of"
#     github dorks -> path:**/<WORD>

paths_wordlist = [
    "",

    "__admin",
    "__init__.py",
    "__main__.py",
    "__pycache__",
    "_.htaccess",
    "_.htpasswd",
    "_",
    "_adm",
    "_admin_",
    "_admin.php",
    "_admin",
    "_archive",
    "_assets",
    "_backup",
    "_bak",
    "_bkp",
    "_build",
    "_cache",
    "_cat/health",
    "_cat/indices",
    "_catalogs",
    "_catalogs/masterpage",
    "_cluster/health",
    "_code",
    "_common.xsl",
    "_common",
    "_conf",
    "_config.yaml",
    "_config.yml",
    "_config",
    "_data.sql",
    "_data",
    "_db_backups",
    "_db_updates",
    "_dbadmin",
    "_default",
    "_dev",
    "_Dockerfile",
    "_files",
    "_functions",
    "_index.php",
    "_index",
    "_install",
    "_layouts",
    "_log",
    "_NOTES",
    "_old",
    "_phpmyadmin",
    "_private",
    "_site.yml",
    "_temp",
    "_test",
    "_tests",
    "_themes",
    "_thumbs",
    "_tmp",
    "_users",
    "!",
    "..;/",
    "..",
    "../../../../../../../../../../../etc/hosts",
    "../../../../../../../../../../etc/hosts",
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd%00",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
    "./../.env",
    "./admin/.",
    ".0",
    ".admin",
    ".ansible",
    ".autotest",
    ".aws",
    ".aws/config",
    ".aws/credentials",
    ".azure/accessTokens.json",
    ".babel.json",
    ".babelrc.js",
    ".babelrc",
    ".backup",
    ".bak",
    ".bash_aliases",
    ".bash_history",
    ".bash_profile",
    ".bashrc",
    ".bin",
    ".bkp",
    ".boto",
    ".bowerrc",
    ".build.sh",
    ".build",
    ".buildlog",
    ".bundle",
    ".cache",
    ".capistrano",
    ".capistrano/metrics",
    ".cargo",
    ".cargo/.crates.toml",
    ".cask",
    ".cert",
    ".cfg",
    ".cfignore",
    ".chef/config.rb",
    ".circleci",
    ".circleci/circle.yml",
    ".circleci/config.yml",
    ".circleci/ssh-config",
    ".classpath",
    ".coafile",
    ".cobalt",
    ".cobalt/sysmanage/../admin/.htaccess",
    ".codacy.yml",
    ".codeclimate.json",
    ".codeclimate.yml",
    ".codecov.yml",
    ".codefresh/codefresh.yml",
    ".codekit-cache",
    ".codeship.yml",
    ".com.old",
    ".com",
    ".components",
    ".composer",
    ".composer/auth.json",
    ".composer/composer.json",
    ".concrete/DEV_MODE",
    ".condarc",
    ".conf",
    ".config.php",
    ".config",
    ".config/docker/config.json",
    ".config/filezilla/sitemanager.xml",
    ".config/gatsby/config.json",
    ".config/gcloud",
    ".config/gcloud/access_tokens.db",
    ".config/gcloud/active_config",
    ".config/gcloud/config_sentinel",
    ".config/gcloud/configurations/config_default",
    ".config/gcloud/credentials.db",
    ".config/gcloud/credentials",
    ".config/gcloud/gce",
    ".config/gcloud/logs",
    ".config/karma.conf.js",
    ".config/pip/pip.conf",
    ".config/sftp.json",
    ".config/stripe/config.toml",
    ".config/yarn/global/package.json",
    ".config/yarn/global/yarn.lock",
    ".configuration",
    ".cookiecutterrc",
    ".cordova/config.json",
    ".core",
    ".coverage",
    ".coveragerc",
    ".cpan",
    ".cpanel",
    ".cpanel/caches/config",
    ".credential",
    ".credentials",
    ".crt",
    ".csproj",
    ".csv",
    ".curlrc",
    ".data",
    ".db.xml",
    ".db.yaml",
    ".db",
    ".deployignore",
    ".deployment",
    ".dev",
    ".devcontainer",
    ".devcontainer/devcontainer.json",
    ".devcontainer/Dockerfile",
    ".doc",
    ".docker",
    ".docker/.env",
    ".docker/config.json",
    ".docker/laravel/app/.env",
    ".dockercfg",
    ".dockerignore",
    ".docs",
    ".dropbox",
    ".dump",
    ".eclipse",
    ".editorconfig",
    ".eggs",
    ".elasticbeanstalk",
    ".env_1",
    ".env_sample",
    ".env-example",
    ".env.backup",
    ".env.bak",
    ".env.dev.local",
    ".env.dev",
    ".env.development.local",
    ".env.development",
    ".env.dist",
    ".env.docker.dev",
    ".env.docker",
    ".env.example",
    ".env.json",
    ".env.local",
    ".env.old",
    ".env.php",
    ".env.prod.local",
    ".env.prod",
    ".env.production.local",
    ".env.production",
    ".env.yaml",
    ".env.yml",
    ".env",
    ".env~",
    ".environment",
    ".envrc",
    ".envs",
    ".error_log",
    ".filetree",
    ".firebaserc",
    ".ftp",
    ".ftppass",
    ".ftpquota",
    ".functions",
    ".gem",
    ".gem/credentials",
    ".gemfile",
    ".gemrc",
    ".gems",
    ".gemspec",
    ".git-credentials",
    ".git.php",
    ".git",
    ".git/COMMIT_EDITMSG",
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/info",
    ".git/logs",
    ".git/objects",
    ".git/packed-refs",
    ".git/refs",
    ".git2",
    ".gitattributes",
    ".gitconfig",
    ".github",
    ".github/.dependabot",
    ".github/dependabot.yml",
    ".github/workflows/docker.yml",
    ".gitignore",
    ".gitignore~",
    ".gitkeep",
    ".gitlab-ci.yml",
    ".gitlab-ci/.env",
    ".gitlab/route-map.yml",
    ".gitmodules",
    ".golangci.yml",
    ".gradle",
    ".gradle/gradle.properties",
    ".graphqlrc.js",
    ".graphqlrc.json",
    ".graphqlrc.toml",
    ".graphqlrc.yaml",
    ".graphqlrc.yml",
    ".graphqlrc",
    ".hash",
    ".hgrc",
    ".history",
    ".hta",
    ".htaccess-dev",
    ".htaccess-old",
    ".htaccess.bak",
    ".htaccess.bak1",
    ".htaccess.old",
    ".htaccess.save",
    ".htaccess.txt",
    ".htaccess",
    ".htaccess~",
    ".htaccess2",
    ".htaccessbak",
    ".htaccessold",
    ".htpasswd.bak",
    ".htpasswd",
    ".htpasswds",
    ".htpasswrd",
    ".httpd.conf",
    ".htusers",
    ".id",
    ".ignore",
    ".install",
    ".irb_history",
    ".irb-history",
    ".irbrc",
    ".key",
    ".keys.yml",
    ".keys",
    ".kube/config",
    ".local",
    ".log.txt",
    ".log",
    ".login",
    ".maintenance",
    ".mypy_cache",
    ".mysql_history",
    ".next",
    ".nodemonignore",
    ".npm",
    ".npmignore",
    ".npmrc",
    ".nuget",
    ".nuxt",
    ".nvmrc",
    ".old",
    ".pass",
    ".passwd",
    ".password",
    ".passwords",
    ".pgpass",
    ".php",
    ".phpmyadmin",
    ".pid",
    ".pip",
    ".prod",
    ".production",
    ".profile",
    ".project-settings.yml",
    ".project",
    ".pryrc",
    ".psqlrc",
    ".pwd.lock",
    ".pwd",
    ".python_history",
    ".rbenv",
    ".remote-sync.json",
    ".remote",
    ".repl_history",
    ".rhosts",
    ".root",
    ".rsync_cache",
    ".rvmrc",
    ".s3cfg",
    ".secret",
    ".secrets",
    ".serverless",
    ".session",
    ".sessions",
    ".settings",
    ".sh_history",
    ".sh",
    ".shrc",
    ".sql",
    ".sqlite_history",
    ".sqlite",
    ".sqlite3",
    ".src",
    ".ssh",
    ".ssh/authorized_keys",
    ".ssh/config",
    ".ssh/google_compute_engine.pub",
    ".ssh/google_compute_engine",
    ".ssh/id_dsa.pub",
    ".ssh/id_dsa",
    ".ssh/id_rsa.pub",
    ".ssh/id_rsa",
    ".ssh/known_hosts",
    ".subversion",
    ".svn",
    ".sync.yml",
    ".tar.gz",
    ".tar",
    ".temp",
    ".tmp",
    ".trash",
    ".txt",
    ".user.ini",
    ".users",
    ".vagrant",
    ".venv",
    ".version",
    ".vimrc",
    ".vscode",
    ".vscode/ftp-sync.json",
    ".vscode/launch.json",
    ".vscode/sftp.json",
    ".vscode/tasks.json",
    ".well-known",
    ".well-known/acme-challenge",
    ".well-known/host-meta.json",
    ".well-known/host-meta",
    ".well-known/oauth-authorization-server",
    ".well-known/openpgpkey",
    ".well-known/pki-validation",
    ".well-known/reload-config",
    ".wget-hsts",
    ".workspace",
    ".wp-cli/config.yml",
    ".xml",
    ".yarnrc",
    ".zcompdump",
    ".zfs",
    ".zip",
    ".zprofile",
    ".zsh_history",
    ".zsh",
    ".zshenv",
    ".zshrc",
    "\\",
    "\\\\",
    "&",
    "%20..",
    "%20admin%20",
    "%2e/admin",
    "%2e%2e//google.com",
    "%3f",
    "%61dmin",
    "%75%73%65%72%2e%70%68%70",
    "%c0",
    "%ff",
    "~",
    "0.html",
    "0.log",
    "0.php",
    "0.sql.tar.gz",
    "0.sql",
    "0.tar.gz",
    "0.tar",
    "0.txt",
    "0.zip",
    "0",
    "01.sql",
    "1-to-2.sql",
    "1.0",
    "1.htaccess",
    "1.htpasswd",
    "1.log",
    "1.php",
    "1.sql.tar.gz",
    "1.sql",
    "1.tar.gz",
    "1.tar",
    "1.txt",
    "1.zip",
    "1",
    "10.php",
    "10.txt",
    "10",
    "11.txt",
    "11",
    "123.txt",
    "123",
    "1234.txt",
    "1234",
    "12345.txt",
    "12345",
    "2-to-3.sql",
    "2.0",
    "2.php",
    "2.sql",
    "2.tar.gz",
    "2.txt",
    "2.zip",
    "2",
    "2020.sql.tar.gz",
    "2020.sql",
    "2020.tar.gz",
    "2020.tar",
    "2020.zip",
    "2020/wp-login.php",
    "2021.sql.tar.gz",
    "2021.sql",
    "2021.tar.gz",
    "2021.tar",
    "2021.zip",
    "2021/wp-login.php",
    "2022.sql.tar.gz",
    "2022.sql",
    "2022.tar.gz",
    "2022.tar",
    "2022.zip",
    "2022/wp-login.php",
    "2023.sql.tar.gz",
    "2023.sql",
    "2023.tar.gz",
    "2023.tar",
    "2023.zip",
    "2023/wp-login.php",
    "3",
    "360",
    "7.php",
    "7.txt",
    "777.php",
    "8.php",
    "8.txt",
    "a.crt",
    "a.htaccess",
    "a.out",
    "a.php",
    "a.sql",
    "a.txt",
    "a",
    "a%5c.aspx",
    "a%5c.php",
    "access.log",
    "access.txt",
    "account.js",
    "account",
    "account/create",
    "account/log-in",
    "account/login",
    "account/new",
    "account/register",
    "account/settings",
    "account/sign-in",
    "account/sign-up",
    "account/signin",
    "account/signup",
    "accounts.sql",
    "accounts.txt",
    "accounts",
    "acme-challenge",
    "acme",
    "actions",
    "activate.sh",
    "activate",
    "actuator",
    "actuator/caches",
    "actuator/dump",
    "actuator/env",
    "actuator/events",
    "actuator/health",
    "actuator/info",
    "actuator/sessions",
    "actuator/status",
    "actuators",
    "actuators/dump",
    "actuators/health",
    "actuators/shutdown",
    "add",
    "addon",
    "addons",
    "adduser",
    "admin.conf",
    "admin.js",
    "admin.passwd",
    "admin.php",
    "admin.txt",
    "ADMIN.txt",
    "admin.zip",
    "admin",
    "ADMIN",
    "admin/../admin",
    "admin/.env",
    "admin/.htaccess",
    "admin/~",
    "admin/config.php",
    "admin/config",
    "admin/index.php",
    "admin/upload.php",
    "admin%20",
    "admin2",
    "administration",
    "after.sh",
    "alter.sql",
    "ansible.cfg",
    "ansible",
    "apache-ssl",
    "apache.conf",
    "apache",
    "api-doc",
    "api-doc/swagger.json",
    "api-docs",
    "api-docs/swagger.json",
    "api.log",
    "api.php",
    "api",
    "api/.env",
    "api/config.js",
    "api/config",
    "api/doc",
    "api/doc/swagger.json",
    "api/docs",
    "api/docs/swagger.json",
    "api/env",
    "api/error_log",
    "api/search",
    "api/user",
    "api/users",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/whoami",
    "apidoc",
    "apidoc/swagger.json",
    "apidocs",
    "apidocs/swagger.json",
    "apiserver-key.pem",
    "apiserver.crt",
    "apiserver.key",
    "apiserver.pem",
    "app.config",
    "app.env",
    "app.js",
    "app.json",
    "app.log",
    "app.php",
    "app.sql.tar.gz",
    "app.sql",
    "app.tar.gz",
    "app.yaml",
    "app.yml",
    "app.zip",
    "app",
    "app/.env",
    "app/.htaccess",
    "app/autoload.php",
    "app/cache",
    "app/composer.json",
    "app/composer.lock",
    "app/config.js",
    "app/config",
    "app/config/config.yml",
    "app/config/database.yml",
    "app/data",
    "app/dev",
    "app/docs",
    "app/log",
    "app/logs",
    "app/models",
    "app/resources",
    "app/src",
    "app/storage",
    "app/tmp",
    "app/vendor",
    "appenv",
    "application.conf",
    "application.log",
    "application.sql.tar.gz",
    "application.sql",
    "application.tar.gz",
    "application.zip",
    "application",
    "application/cache",
    "application/logs",
    "applications",
    "apps.json",
    "apps",
    "apps/test",
    "appsettings.json",
    "apt.sh",
    "archive.php",
    "archive.sh",
    "archive.sql",
    "archive.tar.gz",
    "archive.tar",
    "archive.zip",
    "archive",
    "archives.bak",
    "archives",
    "assets",
    "assets/.env",
    "assets/app.js",
    "assets/application.js",
    "assets/npm-debug.log",
    "attachments",
    "attachments/.htaccess",
    "attachments/index.html",
    "audio",
    "audit.log",
    "auth.php",
    "auth.rb",
    "auth",
    "auth/login",
    "authenticate.php",
    "authenticate",
    "authorize",
    "authorized_keys",
    "auto.log",
    "auto.sh",
    "autobackup.sh",
    "autobuild.sh",
    "autoclean.sh",
    "autoconfig.json",
    "autoconfig.sh",
    "autogen.sh",
    "autoload.php",
    "autorun.sh",
    "aws",
    "azure-pipelines.yml",
    "b.php",
    "b.sql",
    "b.tar.gz",
    "b.txt",
    "b",
    "back.php",
    "back.sql.tar.gz",
    "back.sql",
    "back.tar.gz",
    "back.txt",
    "back.zip",
    "back",
    "backdoor.php",
    "backdoor",
    "backend.php",
    "backend.sql",
    "backend.txt",
    "backend.zip",
    "backend",
    "backend/.env",
    "backup_db.sql",
    "backup.cfg",
    "backup.db",
    "backup.htpasswd",
    "backup.old",
    "backup.sh",
    "backup.sql.tar.gz",
    "backup.sql",
    "backup.sqlite",
    "backup.sqlite3",
    "backup.tar.gz",
    "backup.tar",
    "backup.txt",
    "backup.wp-config.php",
    "backup.zip",
    "backup",
    "backup/.env",
    "backup/data.sql",
    "backup/database.sql",
    "backup/db.sql",
    "backup/dump.sql",
    "backup/mysql.sql",
    "backup/wordpress.sql",
    "backup0",
    "backup1",
    "backup2",
    "backup2019.sql",
    "backup2020.sql",
    "backup2021.sql",
    "backup2022.sql",
    "backup2023.sql",
    "backup2024.sql",
    "backupconfig.php",
    "backups.old",
    "backups.sql",
    "backups.tar.gz",
    "backups.tar",
    "backups.zip",
    "backups",
    "backups/data.sql",
    "backups/database.sql",
    "backups/db_backup.sql",
    "backups/db.sql",
    "backups/dbdump.sql",
    "backups/dump.sql",
    "backups/mysql.sql",
    "backups/site.sql",
    "backups/wordpress.sql",
    "bak.sql.tar.gz",
    "bak.sql",
    "bak.tar.gz",
    "bak.zip",
    "bak",
    "base.sh",
    "base.sql",
    "basic_auth.csv",
    "bd.sql",
    "before_install.sh",
    "before_script.sh",
    "before.sh",
    "beta",
    "billing",
    "bin.json",
    "bin.xml",
    "bin",
    "bin/console",
    "bin/libs",
    "bkp.sql.tar.gz",
    "bkp.sql",
    "bkp.tar.gz",
    "bkp.txt",
    "bkp.zip",
    "bkp",
    "bkup",
    "blobs.sql",
    "blocks.php",
    "blog/.env",
    "boot.sh",
    "bot.txt",
    "bower.json",
    "bugs",
    "bugtracker",
    "build_all.sh",
    "build-all.sh",
    "build-dist.sh",
    "build.log",
    "build.sh",
    "build",
    "build/.env",
    "buildall.sh",
    "builder.sh",
    "bundle.sh",
    "c.txt",
    "ca-certificates.crt",
    "ca-key.pem",
    "ca.crt",
    "ca.key",
    "ca.pem",
    "cache",
    "cache/index.html",
    "cacti.sql",
    "cacti",
    "calendar.sql",
    "cart",
    "categories.sql",
    "cc.php",
    "cert",
    "certs",
    "cfg.php",
    "cfg",
    "cgi-bin",
    "cgi-bin/index.html",
    "cgi-bin/info.php",
    "cgi-bin/login.php",
    "cgi.php",
    "cgi",
    "CHANGELOG.log",
    "CHANGELOG.md",
    "CHANGELOG.txt",
    "CHANGELOG",
    "check_for_upgrade.sh",
    "check-all.sh",
    "check-config.sh",
    "check.php",
    "check.sh",
    "checkout",
    "chef.sh",
    "Cheffile",
    "ci_build.sh",
    "ci.sh",
    "ci",
    "ci/build.sh",
    "ci/pipeline.yml",
    "class",
    "classes.php",
    "clean.sh",
    "clean.sql.tar.gz",
    "clean.sql",
    "clean.tar.gz",
    "clean.zip",
    "cleanup.log",
    "cleanup.sh",
    "clear.sh",
    "clear.sql",
    "clear",
    "cli",
    "client.ovpn",
    "client.sh",
    "client.sql.tar.gz",
    "client.sql",
    "client.tar.gz",
    "client.zip",
    "client",
    "client/.env",
    "clients.sql.tar.gz",
    "clients.sql",
    "clients.sqlite",
    "clients.tar.gz",
    "clients.zip",
    "clients",
    "clone.sh",
    "cloud-config.txt",
    "cloud-provider.yaml",
    "cloud-provider.yml",
    "cloud.txt",
    "cloud",
    "cmd.php",
    "cmd.sh",
    "cmd",
    "cms.sql",
    "cni-conf.json",
    "co",
    "cobalt",
    "code.php",
    "code",
    "codeception.yml",
    "codes",
    "com",
    "command.php",
    "command",
    "comment",
    "comments.sql",
    "comments",
    "common.js",
    "common.php",
    "common",
    "company.sql",
    "component.php",
    "components.php",
    "components",
    "composer.json",
    "composer.lock",
    "composer.php",
    "conf.php",
    "conf",
    "conf/.env",
    "config.inc.php",
    "config.js",
    "config.json",
    "config.local",
    "config.log",
    "config.php",
    "config.sh",
    "config.txt",
    "config.xml",
    "config.yaml",
    "config.yml",
    "config",
    "config/.env",
    "config/app.php",
    "config/app.yml",
    "config/aws.yml",
    "config/database.yml",
    "config/db.js",
    "config/db.json",
    "config/db.yml",
    "config/default.json",
    "config/default.yml",
    "config/deploy.sh",
    "config/routes.php",
    "config/s3.json",
    "config/s3.yaml",
    "config/s3.yml",
    "config/secrets.json",
    "config/secrets.yml",
    "config/services.json",
    "config/services.php",
    "config/services.yml",
    "config/xml",
    "configs",
    "configuration.php",
    "configuration",
    "console.log",
    "console",
    "construct",
    "container",
    "containers",
    "content.json",
    "content.php",
    "content.sql",
    "content",
    "CONTRIBUTORS",
    "controller/config",
    "controllers.php",
    "controllers",
    "controlpanel",
    "controls",
    "convert.sh",
    "cookie.php",
    "cookie",
    "cookies",
    "copy.sh",
    "copy.sql",
    "core.js",
    "core.php",
    "core",
    "cpanel",
    "create_db.sql",
    "create_tables.sql",
    "create.sh",
    "create.sql",
    "create",
    "credentials.csv",
    "credentials.json",
    "credentials.txt",
    "credentials",
    "cron.log",
    "cron.php",
    "cron.sh",
    "cron",
    "csv",
    "custom",
    "customer",
    "customers.csv",
    "customers.log",
    "customers.sql",
    "customers.sqlite",
    "customers.txt",
    "customers",
    "dashboard.php",
    "dashboard",
    "data.db",
    "data.php",
    "data.sql.tar.gz",
    "data.sql",
    "data.sqlite",
    "data.sqlite3",
    "data.tar.gz",
    "data.txt",
    "data.zip",
    "data",
    "data/.env",
    "data/backup",
    "data/backups",
    "data/cache",
    "data/db",
    "data/files",
    "data/logs",
    "data/sessions",
    "database_backup.sql",
    "database.csv",
    "database.db",
    "database.php",
    "database.sh",
    "database.sql.tar.gz",
    "database.sql",
    "database.sqlite",
    "database.sqlite3",
    "database.txt",
    "database.yml",
    "database.zip",
    "database",
    "databases.yml",
    "datastream",
    "db_backup.sql.tar.gz",
    "db_backup.sql",
    "db_backup.tar.gz",
    "db_backup.tar",
    "db_backup.zip",
    "db_backups",
    "db_data.sql",
    "db_init.sql",
    "db_install.sql",
    "db_update.sql",
    "db.csv",
    "db.log",
    "db.php",
    "db.sql.tar.gz",
    "db.sql",
    "db.sqlite",
    "db.sqlite3",
    "db.tar.gz",
    "db.tar",
    "db.yaml",
    "db.yml",
    "db.zip",
    "db",
    "db/dump.sql",
    "db/phpmyadmin",
    "dbdump.sql.tar.gz",
    "dbdump.sql",
    "dbdump.tar.gz",
    "dbdump.tar",
    "dbdump.zip",
    "dbtables.sql",
    "debug.log",
    "debug.php",
    "debug.sh",
    "debug.sql",
    "debug.tar.gz",
    "debug.txt",
    "debug.xml",
    "debug.zip",
    "debug",
    "debugbar",
    "debugger.php",
    "debugger",
    "default.config",
    "default.log",
    "default.sql",
    "default",
    "delete.php",
    "delete.sh",
    "delete.sql",
    "delete",
    "demo.php",
    "demo.sh",
    "demo.sql",
    "demo",
    "demo/.env",
    "dependencies.sh",
    "deploy_snapshot.sh",
    "deploy.env",
    "deploy.sh",
    "deploy",
    "deploy/.env",
    "deployment-config.json",
    "deps.sh",
    "dev-web",
    "dev.log",
    "dev.php",
    "dev.sh",
    "dev.sql.tar.gz",
    "dev.sql",
    "dev.tar.gz",
    "dev.tar",
    "dev.zip",
    "dev",
    "development",
    "dist",
    "dl",
    "doc",
    "doc/api",
    "docker-build.sh",
    "docker-compose.yml",
    "docker-run.sh",
    "docker.sh",
    "docker",
    "docker/.env",
    "Dockerfile",
    "docs",
    "docs/api",
    "docs/swagger.json",
    "documents",
    "dotfiles/.env",
    "download.php",
    "download.sh",
    "download",
    "downloads",
    "drop.sql",
    "dump.json",
    "dump.log",
    "dump.sh",
    "dump.sql.tar.gz",
    "dump.sql",
    "dump.sqlite",
    "dump.sqlite3",
    "dump.tar.gz",
    "dump.tar",
    "dump.txt",
    "dump.zip",
    "dump",
    "dumps",
    "e.php",
    "e.txt",
    "e",
    "edit.php",
    "edit",
    "editor.js",
    "editor.php",
    "editor",
    "elasticsearch",
    "email.php",
    "email",
    "emails",
    "employees",
    "en/.env",
    "enable",
    "entries",
    "env.bak",
    "env.conf",
    "env.js",
    "env.json",
    "env",
    "environment.conf",
    "err.log",
    "error.aspx",
    "error.log",
    "error.php",
    "error.txt",
    "errors.log",
    "errors.php",
    "etc",
    "etc/passwd",
    "exec.sh",
    "explore",
    "export.js",
    "export.php",
    "export.sh",
    "export.sql.tar.gz",
    "export.sql",
    "export.sqlite",
    "export.sqlite3",
    "export.tar.gz",
    "export.tar",
    "export.txt",
    "export.zip",
    "export",
    "export/.env",
    "extra",
    "f.php",
    "f.txt",
    "f",
    "factory",
    "feed.json",
    "feed.xml",
    "fetch.js",
    "fetch",
    "file_upload.php",
    "file.php",
    "file.sql",
    "files.php",
    "files.txt",
    "files.zip",
    "files",
    "form.php",
    "forms.php",
    "foto",
    "frontend/.env",
    "ftp.txt",
    "ftp",
    "ftpsync.settings",
    "functions.php",
    "functions",
    "functions/.env",
    "g.txt",
    "g",
    "gallery",
    "Gemfile",
    "general.php",
    "generate.sh",
    "get.php",
    "get.sh",
    "get",
    "git.sh",
    "git",
    "github",
    "gitlab-ci.yml",
    "gitlab",
    "gitlog",
    "go.mod",
    "google",
    "grafana",
    "graph",
    "graphiql",
    "graphql.config.json",
    "graphql.config.yaml",
    "graphql.config.yml",
    "graphql.json",
    "graphql.yaml",
    "graphql.yml",
    "graphql",
    "guest",
    "guides",
    "h.php",
    "h.txt",
    "h",
    "handlers",
    "haproxy",
    "head.php",
    "head",
    "header.php",
    "health",
    "helper.php",
    "helper.sh",
    "helpers.sh",
    "HISTORY.md",
    "HISTORY.txt",
    "home",
    "Homestead.json",
    "Homestead.yaml",
    "host.key",
    "HOWTO.txt",
    "htaccess.txt",
    "html.bak",
    "html.php",
    "htpasswd.bak",
    "htpasswd",
    "http",
    "httpd.conf",
    "httpd.ini",
    "i.php",
    "i.txt",
    "i.zip",
    "i",
    "iam",
    "id_rsa.pub",
    "id_rsa",
    "image_upload",
    "image.php",
    "image",
    "images.bak",
    "images.php",
    "images.zip",
    "images",
    "img",
    "import.js",
    "import.php",
    "import.sql.tar.gz",
    "import.sql",
    "import.sqlite",
    "import.sqlite3",
    "import.tar.gz",
    "import.tar",
    "import.txt",
    "import.zip",
    "import",
    "imports",
    "include",
    "includes",
    "includes/.htaccess",
    "includes/config.php",
    "index.js",
    "index.php5",
    "info.json",
    "info.log",
    "info.php",
    "info.txt",
    "init_db.sh",
    "init_db.sql",
    "init-db.sh",
    "init-db.sql",
    "init.sh",
    "init.sql",
    "init",
    "insert.sql",
    "inspector",
    "install.bak",
    "install.log",
    "install.md",
    "INSTALL.md",
    "install.old",
    "install.php",
    "install.sh",
    "install.sql",
    "install.txt",
    "INSTALL.txt",
    "install",
    "INSTALL",
    "install/.env",
    "installer.php",
    "interface",
    "interfaces",
    "internal",
    "internals",
    "intra",
    "intranet",
    "invoice",
    "invoices",
    "invoicing",
    "j.php",
    "j.txt",
    "javascript",
    "jboss",
    "jenkins.sh",
    "jenkins.yaml",
    "jenkins.yml",
    "join",
    "js",
    "js/.env",
    "js/app.js",
    "js/application.js",
    "js/base.js",
    "js/build",
    "js/bundle",
    "js/bundles",
    "js/common.js",
    "js/index.js",
    "k.php",
    "k.txt",
    "key.js",
    "key.pem",
    "key.php",
    "keys.yml",
    "keys",
    "keys/id_dsa.pub",
    "keys/id_dsa",
    "keys/id_rsa.pub",
    "keys/id_rsa",
    "kube-apiserver-key.pem",
    "kubectl.sh",
    "kubelet.sh",
    "kubernetes",
    "kvm.sh",
    "l.php",
    "l.txt",
    "l",
    "last.txt",
    "last.zip",
    "latest.txt",
    "latest.zip",
    "layout",
    "level",
    "lib.sh",
    "lib",
    "lib/.env",
    "libraries",
    "library",
    "libs.json",
    "libs.xml",
    "libs",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENSE",
    "lighttpd.conf",
    "list",
    "load.php",
    "load.sh",
    "log-in",
    "log.sql",
    "log.txt",
    "log.zip",
    "log",
    "login.do",
    "login.html",
    "login.js",
    "login.php",
    "login.sh",
    "login.txt",
    "login",
    "login/oauth",
    "logins.txt",
    "logon",
    "logs.txt",
    "logs",
    "logs/access.log",
    "logs/error.log",
    "logs/errors.log",
    "m.php",
    "m.txt",
    "m",
    "mail.log",
    "mail.php",
    "mail",
    "mailer.php",
    "main.do",
    "main.js",
    "main.log",
    "main.php",
    "main.sh",
    "main.sql",
    "maintenance.php",
    "maintenance",
    "make.sh",
    "Makefile",
    "manage.aspx",
    "manage.php",
    "manage.sh",
    "manage",
    "manager.php",
    "manager.sh",
    "manager",
    "master.log",
    "master.sh",
    "master.tar.gz",
    "master.tar",
    "master.zip",
    "media.zip",
    "media",
    "memberlist",
    "members.aspx",
    "members.csv",
    "members.html",
    "members.php",
    "members.txt",
    "members.zip",
    "members",
    "members/login.php",
    "members/login",
    "members/signin",
    "merchant",
    "mercurial",
    "messages",
    "meta.json",
    "meta.xml",
    "meta.yaml",
    "meta.yml",
    "meta/main.yml",
    "migrate.php",
    "migrate.sh",
    "migrations",
    "misc",
    "mk.sh",
    "mobile",
    "mod",
    "model.php",
    "models.php",
    "models",
    "mods",
    "modules.php",
    "modules",
    "mongo",
    "mongodb",
    "monit",
    "monitor.sh",
    "monitor",
    "my.cnf",
    "my.php",
    "my.sql",
    "my",
    "myadmin",
    "mysql.log",
    "mysql.php",
    "mysql.sh",
    "mysql.sql.tar.gz",
    "mysql.sql",
    "mysql.tar.gz",
    "mysql.tar",
    "mysql.tmp",
    "mysql.txt",
    "mysql.zip",
    "mysql",
    "n.php",
    "n.txt",
    "n",
    "new_install.sh",
    "new_server.sh",
    "new.php",
    "new.sh",
    "new.sql.tar.gz",
    "new.sql",
    "new.tar.gz",
    "new.tar",
    "new.tmp",
    "new.zip",
    "new",
    "new/.env",
    "newsletter.sql",
    "newsletter",
    "next",
    "nginx_access.log",
    "nginx.conf",
    "nginx.sh",
    "nginx.txt",
    "nginx/.env",
    "node_modules",
    "node.sh",
    "node",
    "node/1",
    "nohup.out",
    "note.txt",
    "NOTE.txt",
    "notes.txt",
    "NOTES.txt",
    "npm-debug.log",
    "o.php",
    "o.txt",
    "o",
    "oauth",
    "oauth/authorize",
    "oauth/token",
    "old.sql.tar.gz",
    "old.sql",
    "old.tar.gz",
    "old.tar",
    "old.tmp",
    "old.zip",
    "old",
    "old/.env",
    "old/.htaccess",
    "old/.htpasswd",
    "on",
    "openssl",
    "openstack",
    "operations",
    "oracle.sql.tar.gz",
    "oracle.sql",
    "order.php",
    "order.txt",
    "ORDER.txt",
    "order",
    "orders.csv",
    "orders.php",
    "orders.sql.tar.gz",
    "orders.sql",
    "orders.txt",
    "orders",
    "out.log",
    "out.php",
    "out.txt",
    "out",
    "output.log",
    "owncloud",
    "owncloud/.env",
    "p.php",
    "p.txt",
    "p",
    "pack.sh",
    "package-lock.json",
    "package.json",
    "package.sh",
    "package",
    "page.php",
    "pages.php",
    "pages",
    "panel.aspx",
    "panel.html",
    "panel.php",
    "panel",
    "pass.php",
    "pass.txt",
    "pass",
    "passwd",
    "password.php",
    "password.txt",
    "PASSWORD.txt",
    "passwords.txt",
    "passwords",
    "patch.sh",
    "payment.php",
    "payment",
    "payments.php",
    "payments",
    "pdf",
    "pdfs",
    "people",
    "pg_hba.conf",
    "pgsql.txt",
    "photo.php",
    "photo",
    "photos.php",
    "photos.zip",
    "photos",
    "php.ini",
    "phpinfo.php",
    "phpmyadmin",
    "phpMyAdmin",
    "pics",
    "picture",
    "pictures",
    "pkg.sh",
    "plugins",
    "pma",
    "portal",
    "post.php",
    "post",
    "posts.json",
    "posts.php",
    "pp.php",
    "pp",
    "prebuild.sh",
    "prepublish.sh",
    "preview",
    "private.key",
    "private.php",
    "private",
    "pro",
    "process.sh",
    "prod.sql.tar.gz",
    "prod.sql",
    "prod.tar.gz",
    "prod.tar",
    "prod.zip",
    "prod",
    "product.json",
    "production.sql.tar.gz",
    "production.sql",
    "production.tar.gz",
    "production.tar",
    "production.zip",
    "production",
    "products.json",
    "professional",
    "profile.php",
    "profile",
    "profile/edit",
    "profiles",
    "project.xml",
    "projects",
    "protected",
    "protected/.env",
    "pub",
    "public",
    "publish.sh",
    "puppet.conf",
    "put",
    "pw.txt",
    "pwd.txt",
    "q.php",
    "q.sql",
    "q.txt",
    "q",
    "query.log",
    "query.sql.tar.gz",
    "query.sql",
    "query.tar.gz",
    "query.tar",
    "query.zip",
    "query",
    "queue",
    "r.php",
    "r.txt",
    "r",
    "rabbitmq",
    "Rakefile",
    "read",
    "readme.md",
    "README.md",
    "readme.rst",
    "README.rst",
    "readme.txt",
    "README.txt",
    "readme",
    "README",
    "rebuild.sh",
    "record",
    "records.log",
    "records.zip",
    "records",
    "redis.conf",
    "redis",
    "register",
    "RELEASE-NOTES.md",
    "release-notes.txt",
    "RELEASE-NOTES.txt",
    "release.sh",
    "release.zip",
    "remote.sh",
    "remote",
    "remove.sh",
    "remove",
    "renew",
    "reply",
    "repo",
    "report.log",
    "report.sql",
    "report",
    "reports",
    "repos",
    "repository",
    "req",
    "request.log",
    "requests.log",
    "requirements.txt",
    "reset.sh",
    "reset",
    "resources",
    "resources/.env",
    "rest-api",
    "rest",
    "rest/v1",
    "restapi",
    "restart.sh",
    "restore.sh",
    "restrict",
    "restricted",
    "result.log",
    "result.sql",
    "results.sql",
    "results.zip",
    "results",
    "retrieve",
    "robots.txt../admin",
    "robots.txt..%3b",
    "robots.txt",
    "robots.txt/../admin",
    "robots.txt/..%3b",
    "robots.txt/%2e%2e%3b",
    "robots.txt%2e%2e%3b",
    "root.js",
    "root.php",
    "root",
    "root/.env",
    "RootCA.crt",
    "roundcube",
    "router.php",
    "routes.ini",
    "routes.php",
    "routes/.env",
    "rpm-install.sh",
    "rpm.sh",
    "rpm",
    "rsa",
    "rsync.sh",
    "rsync",
    "run-all.sh",
    "run-test.sh",
    "run-tests.sh",
    "run.log",
    "run.sh",
    "run",
    "runall.sh",
    "runserver.sh",
    "runtest.sh",
    "runtests.sh",
    "s.php",
    "s.txt",
    "s3.json",
    "s3.yaml",
    "s3.yml",
    "sales.csv",
    "sales",
    "sample",
    "save.sql.tar.gz",
    "save.sql",
    "save.tar.gz",
    "save.tar",
    "save.zip",
    "schema.sql",
    "schema.yaml",
    "schema.yml",
    "schema.zip",
    "script",
    "script/.env",
    "scripts",
    "scripts/.env",
    "scripts/main.js",
    "scripts/rpm-install.sh",
    "scripts/setup.sh",
    "search.php",
    "search",
    "secret.txt",
    "secret",
    "secrets.env",
    "secrets.txt",
    "secrets",
    "secure",
    "secure/.htaccess",
    "security/login",
    "select",
    "sendmail.php",
    "sendmail",
    "serve.sh",
    "server.cert",
    "server.crt",
    "server.js",
    "server.key",
    "server.log",
    "server.ovpn",
    "server.php",
    "server.sh",
    "server.zip",
    "serverless.yaml",
    "serverless.yml",
    "service.sh",
    "service.yaml",
    "service.yml",
    "session",
    "sessions.sql",
    "sessions",
    "set",
    "settings.json",
    "settings.php",
    "settings.sh",
    "settings.txt",
    "SETTINGS.txt",
    "settings.yaml",
    "settings.yml",
    "settings",
    "setup.cfg",
    "setup.php",
    "setup.sh",
    "setup.txt",
    "SETUP.txt",
    "setup",
    "sftp-config.json",
    "show",
    "sign_in",
    "sign_up",
    "sign-in",
    "sign-up",
    "sign",
    "signin",
    "signin/oauth",
    "signup",
    "site.sql",
    "site.zip",
    "sitemap.txt",
    "sites",
    "source",
    "sources",
    "sql.php",
    "sql.txt",
    "sql.zip",
    "sqlite",
    "sqlite3",
    "src",
    "src/.env",
    "src/.htaccess",
    "src/app.js",
    "src/config.js",
    "src/go.mod",
    "src/index.js",
    "src/server.js",
    "ssh",
    "ssh/config",
    "ssl",
    "staff",
    "start_server.sh",
    "start-server.sh",
    "start.php",
    "start.sh",
    "start",
    "startup.cfg",
    "static..",
    "static../admin",
    "static..%3b",
    "static.php",
    "static",
    "static/../admin",
    "static/..%3b",
    "static/.env",
    "static/%2e%2e",
    "static%2e%2e%3b",
    "stats",
    "STATUS.md",
    "status.php",
    "STATUS.txt",
    "status",
    "stop.sh",
    "storage",
    "storage/.env",
    "stream.m3u8",
    "stream",
    "streaming",
    "stripe",
    "sub",
    "submit",
    "subscribe",
    "supervisor",
    "svn",
    "swagger-ui.json",
    "swagger-ui",
    "swagger-ui/swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger",
    "swagger/v1",
    "sync.yaml",
    "sync.yml",
    "sysadmin",
    "system.log",
    "system.php",
    "system.sh",
    "system",
    "system/.env",
    "system/admin",
    "system/cache",
    "system/config",
    "system/console",
    "system/log",
    "system/logs",
    "systemadmin",
    "t.php",
    "t.txt",
    "t",
    "table.sql",
    "tables.sql.tar.gz",
    "tables.sql",
    "tables.tar.gz",
    "tables.tar",
    "tables.zip",
    "task.sh",
    "tasks.php",
    "tasks.sh",
    "tasks",
    "team",
    "temp.php",
    "temp.sql",
    "temp",
    "temp/.env",
    "test_",
    "test.bak",
    "test.html",
    "test.old",
    "test.php",
    "test.sh",
    "test.sql.tar.gz",
    "test.sql",
    "test.tar.gz",
    "test.tar",
    "test.txt",
    "test.zip",
    "test",
    "test/.env",
    "test1.html",
    "test1.php",
    "test1",
    "test2.html",
    "test2.php",
    "test2",
    "testing",
    "tests.sh",
    "tests",
    "thumbnails",
    "thumbs",
    "ticket",
    "tickets",
    "tmp.php",
    "tmp.sql",
    "tmp",
    "tmp/.env",
    "todo.txt",
    "TODO.txt",
    "token.json",
    "token",
    "tokens",
    "tools.sh",
    "tools",
    "tox.ini",
    "transfer.sql",
    "trash",
    "two",
    "txt",
    "u.sql",
    "u.txt",
    "up.php",
    "up.sh",
    "update-all.sh",
    "update-translations.sh",
    "update-vendor.sh",
    "update-version.sh",
    "UPDATE.md",
    "update.php",
    "update.sh",
    "update.sql.tar.gz",
    "update.sql",
    "update.tar.gz",
    "update.txt",
    "UPDATE.txt",
    "update.zip",
    "update",
    "updates",
    "upgrade.md",
    "UPGRADE.md",
    "upgrade.php",
    "upgrade.sh",
    "upgrade.sql",
    "upgrade.txt",
    "UPGRADE.txt",
    "upgrade",
    "upload.php",
    "upload.sh",
    "upload",
    "upload/.env",
    "uploads",
    "uploads/.env",
    "user_uploads",
    "user.aspx",
    "user.php",
    "user.sql",
    "user.txt",
    "user",
    "user/0",
    "user/1",
    "user/2",
    "user/admin",
    "user/join",
    "user/login.php",
    "user/login",
    "user/register",
    "user/signup",
    "user1",
    "useradmin",
    "userinfo.php",
    "userinfo",
    "userlogin.aspx",
    "userlogin.do",
    "userlogin.php",
    "userlogin",
    "username",
    "usernames.txt",
    "users.aspx",
    "users.html",
    "users.json",
    "users.php",
    "users.sql.tar.gz",
    "users.sql",
    "users.tar.gz",
    "users.tar",
    "users.txt",
    "users.yml",
    "users.zip",
    "users",
    "users/0",
    "users/1",
    "users/2",
    "users/admin",
    "users/join",
    "users/login.php",
    "users/login",
    "users/register",
    "users/signup",
    "util.sh",
    "utils",
    "v.php",
    "v.txt",
    "v",
    "v0",
    "v1.0",
    "v1.1",
    "v1",
    "v1/.env",
    "v1/api-docs",
    "v1/api",
    "v1/explorer",
    "v1/graphiql",
    "v1/graphql",
    "v1/playground",
    "v1/swagger-ui.html",
    "v1/swagger.json",
    "v10",
    "v2.0",
    "v2",
    "v2/.env",
    "v2/api-docs",
    "v2/graphiql",
    "v2/graphql",
    "v2/keys",
    "v2/playground",
    "v2/swagger.json",
    "v3",
    "v3/graphiql",
    "v3/graphql",
    "v3/playground",
    "v3alpha",
    "v4",
    "v5",
    "v8.log",
    "vagrant.sh",
    "Vagrantfile",
    "validate",
    "var",
    "var/backups",
    "var/cache",
    "var/log",
    "var/logs",
    "var/sessions",
    "vars.sh",
    "vendor.sh",
    "vendor",
    "vendor/bundle",
    "vendor/composer",
    "vendor/plugins",
    "venv",
    "ver.php",
    "verify.sh",
    "verify",
    "VERSION.md",
    "version.php",
    "version.txt",
    "VERSION.txt",
    "version",
    "VERSIONS.md",
    "versions.txt",
    "VERSIONS.txt",
    "videos",
    "view.php",
    "view",
    "viewer",
    "views",
    "virtualenv",
    "virtualenvs",
    "vpn",
    "web-dev",
    "web.config",
    "web.sql",
    "web.zip",
    "web",
    "webadmin.aspx",
    "webadmin.js",
    "webadmin.php",
    "webadmin",
    "webapp",
    "webdav",
    "webdev",
    "webdisk",
    "webmaster",
    "webpack.js",
    "website.sql",
    "website.zip",
    "website",
    "welcome",
    "well-known",
    "widgets",
    "wiki",
    "wordpress.sql",
    "wordpress.txt",
    "wordpress.zip",
    "wordpress",
    "works",
    "workspace",
    "workspaces",
    "wp-admin",
    "wp-admin/admin-ajax.php",
    "wp-admin/admin-post.php",
    "wp-admin/admin.php",
    "wp-admin/install.php",
    "wp-admin/post-new.php",
    "wp-admin/setup-config.php",
    "wp-config 1.php",
    "wp-config copy.php",
    "wp-config-back.php",
    "wp-config-backup.php",
    "wp-config-bkp.php",
    "wp-config-old.php",
    "wp-config.bak",
    "wp-config.bkp",
    "wp-config.conf",
    "wp-config.new",
    "wp-config.old.php",
    "wp-config.php.bak",
    "wp-config.php.zip",
    "wp-config.php",
    "wp-config.php0",
    "wp-config.php1",
    "wp-config.zip",
    "wp-content",
    "wp-content/cache",
    "wp-content/debug.log",
    "wp-content/plugins",
    "wp-cron.php",
    "wp-includes",
    "wp-login.php",
    "wp",
    "ws",
    "www_root",
    "www-data",
    "www",
    "wwwroot",
    "wwwstat",
    "x.php",
    "x.txt",
    "x",
    "xml",
    "xx.php",
    "xxx.php",
    "xxx",
    "y.php",
    "y.txt",
    "y",
    "yarn-error.log",
    "yarn.lock",
    "yum.log",
    "yum.sh",
    "z.php",
    "z.txt",
    "z",
    "zebra.conf",
    "zimbra",
    "zip",
    "zone.sql",
    "zone",
]