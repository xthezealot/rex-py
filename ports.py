import asyncio
import re

common_ports = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    80:    "http",
    443:   "http",
    445:   "smb",
    1433:  "mssql",
    1521:  "oracle",
    2375:  "docker",
    3000:  "http",
    3306:  "mysql",
    5000:  "http",
    5432:  "postgresql",
    8000:  "http",
    8008:  "http",
    8080:  "http",
    8081:  "http",
    8443:  "http",
    8888:  "http",
    9200:  "elasticsearch",
    10250: "kubernetes",
    27017: "mongodb",
}

interestingContentTypes = [
    "application/gzip",
    "application/javascript",
    "application/json",
    "application/msword",
    "application/octet-stream",
    "application/pdf",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/xhtml+xml",
    "application/xml",
    "application/zip",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
]

downloadableContentTypes = [
    "application/javascript",
    "application/json",
    "application/xhtml+xml",
    "application/xml",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
]


async def port_info(host, port):
    reader, writer = None, None

    try:
        # conn = socket.create_connection((host, port), timeout=1)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)
        print(f"port {port} is open on {host}")
    # except (ConnectionRefusedError, TimeoutError):
    except (ConnectionRefusedError, OSError):
        print(f"port {port} closed on {host}")
        return

    info = {"name": common_ports.get(port, "unknown")}

    match port:
        case 21:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                first_line = data.decode(errors="ignore").split("\n", 1)[0]
                if len(first_line) >= 3:
                    info["version"] = first_line[3:].strip()
            except asyncio.TimeoutError:
                pass

        case 22:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                pattern = re.compile(r"(?im)^.*ssh.*$")
                info["version"] = pattern.search(
                    data.decode(errors="ignore")).group().strip()
            except asyncio.TimeoutError:
                pass

    if writer:
        writer.close()
        await writer.wait_closed()

    return info
