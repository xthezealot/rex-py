from fabric import Connection, task  # type: ignore


@task
def deploy(ctx):  # type: ignore
    host = "168.119.99.198"  # "neshek.xxxxxxx.dev"
    user = "root"
    dir = "/root/bb/rex"

    c = Connection(host, user=user)

    c.run(f"mkdir -p {dir}")

    c.local(f"rsync -av *.py requirements.txt {user}@{host}:{dir}")  # type: ignore

    c.put("cmd.sh", "/usr/local/bin/rex")  # type: ignore
    c.run("chmod +x /usr/local/bin/rex")

    with c.cd(dir):  # type: ignore
        if not c.run("test -d venv", warn=True):
            c.run("python3 -m venv venv")

        c.run("venv/bin/pip install -r requirements.txt")
